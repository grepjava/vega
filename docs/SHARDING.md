# Sharding

`Runtime.sharded` runs one server as several **shard processes** under a **supervisor**. Each shard has its own multi-threaded Vega runtime on its own share of the CPUs. The supervisor starts the shards, restarts any that crash, and passes signals on to them. This page covers when that pays off, how shards are launched and share their listening sockets on each platform, and how the supervisor behaves.

## When to shard

Shard when one of these matters more than the cost below:

- **Fault isolation.** A trap (a failed precondition, an out-of-bounds index, `fatalError`) kills a process. With K shards it takes down 1/K of the connections, and the supervisor brings the shard back. A single runtime loses everything.
- **Cache locality.** By default each shard covers one cache domain and pins its workers there (Linux), so work stealing never moves a task to a core that doesn't share its last-level cache.
- **Restarts without downtime.** SIGHUP replaces the shards one at a time, so the server keeps accepting throughout.

The cost: shards share no memory. Caches, connection pools and counters are per shard, and anything global needs a store outside the process. Each shard also pays for its own runtime and heap.

On a machine with one cache domain and a server whose code doesn't trap, one runtime (`Runtime(workers:)`) is simpler and just as fast.

## A sharded server

```swift
import Vega

var config = ShardConfiguration()            // one shard per cache domain
config.listeners = [.tcp(port: 8080)]
config.shutdownGracePeriod = .seconds(10)
config.onEvent = { event in print("supervisor:", event) }

Runtime.sharded(config) { shard in
    do {
        try shard.runtime.block { () async throws(IOError) in
            var terminate = try Runtime.signals(SIGTERM)
            let server = try TCPServer.serve(try shard.listener()) { await handle($0) }
            // Drain on SIGTERM (a stop, or a SIGHUP reload), inside the
            // supervisor's grace period.
            try? await terminate.recv()
            await server.shutdown(gracePeriod: .seconds(5))
        }
    } catch {
        print("shard \(shard.index): \(error)")
        exit(1) // non-zero: the supervisor restarts it
    }
}
```

- Call `Runtime.sharded` first thing in a synchronous `main`, before any thread or task exists. The supervisor checks this: on Linux it reads `/proc/self/status`, on Darwin it uses `task_threads`.
- The supervisor never runs the closure. Each shard runs it on its main thread with `shard.runtime`, and exits 0 when it returns.
- `shard.listener(i)` gives a `TCPListener` for `config.listeners[i]` on the shard's runtime. Call it again for more accept loops. `shard.port(i)` is the port, which is useful when you asked for port 0.
- `shard.index` (0 ..< `shard.count`) stays the same when a shard is restarted.
- Shards get SIGTERM at its default action, which ends the process at once. To finish open connections first, catch it as above with `Runtime.signals(SIGTERM)` and shut the server down within `shutdownGracePeriod`.

## Options

| `ShardConfiguration` | Default | Meaning |
|---|---|---|
| `shards` | one per cache domain | Number of shard processes; 0 runs in-process (see below). `VEGA_SHARDS` overrides it |
| `workersPerShard` | the shard's CPU count | Workers in each shard's runtime |
| `pinThreads` | `true` | Pin each shard's workers to its CPUs (Linux; Darwin can't pin) |
| `listeners` | `[]` | Listening sockets the shards serve (`.tcp(host:port:backlog:)`) |
| `listenerMode` | `.automatic` | How shards share the listeners; see below |
| `launch` | `.automatic` | How shard processes start; see below |
| `restartCrashed` | `true` | Restart a shard that crashes |
| `shutdownGracePeriod` | 30 s | Time between SIGTERM and SIGKILL on stop |
| `name` | `"vega-s"` | Thread name prefix (shard i's workers are `vega-s<i>-<n>`) |
| `onEvent` | `nil` | Called in the supervisor for each `ShardEvent` |

**Cache domains.** On Linux they are read from sysfs: CPUs that share a last-level cache (L3 on most x86 parts) form one domain. On Darwin they are the performance levels (`hw.perflevelN.logicalcpu`), each a cluster with its own L2. An M1 has two domains of 4 CPUs, so the default there is 2 shards of 4 workers. Elsewhere, or when the system reports nothing, all CPUs form one domain. If `shards` doesn't match the number of domains, the CPUs are split into even contiguous slices.

## Running without shards

With `shards` 0, `Runtime.sharded` starts no supervisor and no shard processes. It runs the closure once, in the calling process, the way a plain Tokio-style runtime would:

- The closure gets shard 0 of 1. `shard.runtime` is a multi-threaded runtime with `workersPerShard` workers, or one per CPU. Its threads are never pinned.
- `config.listeners` are bound in this process, once each. `shard.listener(i)` works as in a shard, and every call shares the one socket.
- Nothing restarts the process, and the supervisor's signal handling doesn't apply. A `Runtime.signals(SIGTERM)` drain in the closure works the same as in a shard.
- There is no single-thread check, so threads may already exist.
- When the closure returns, the process exits 0.

When code leaves `config.shards` nil, the environment variable `VEGA_SHARDS` sets it. One `main` therefore runs as one process or as K shards, chosen at deploy time:

```sh
VEGA_SHARDS=0 ./server   # one process, one runtime
VEGA_SHARDS=4 ./server   # a supervisor and 4 shards
./server                 # whatever ShardConfiguration.shards says
```

A value that isn't a count ends the process with exit code 1 and a message.

## Launch modes

| `ShardLaunch` | How a shard starts | Default on |
|---|---|---|
| `.fork` | `fork()`: the shard carries on from the `Runtime.sharded` call with a copy of the supervisor's memory | Linux |
| `.exec` | `posix_spawn` of the same executable with the same arguments: the shard runs `main` again, and `Runtime.sharded` runs the closure at once | Darwin and others |

**Why exec on Darwin.** After a `fork` without `exec`, a child may only make async-signal-safe calls. Some libsystem state the Swift runtime uses, such as os_log's preferences, isn't valid in the child. On an M1, 6 of 30 forked shards died with SIGSEGV in `_os_log_preferences_refresh` on their first protocol-conformance lookup. Exec-launched shards passed 10 out of 10 runs of `vega-shard-check` with no crashes. Linux libraries don't have this problem, so Linux keeps `fork` as the default, which is faster to start. `.exec` works on Linux too.

**What exec mode requires.** Every shard runs `main` again up to the `Runtime.sharded` call, so the code before that call must be deterministic and free of side effects. Don't open files, log a banner, or read configuration that may change between shard starts. The shard then runs the closure with the configuration and closure that its own run of `main` built.

How the supervisor hands an exec'd shard its state:

- Environment variables:
  - `VEGA_SHARD`: the shard's index.
  - `VEGA_SHARD_COUNT`: the number of shards.
  - `VEGA_SHARD_CPUS`: the shard's CPU list.
  - `VEGA_SHARD_FDS`: each listener's descriptor and port.
  - `VEGA_SHARD_PARENT`: the supervisor's pid.

  The shard removes all of them before it runs the closure, so its own child processes don't see them.
- File descriptors: shared listening sockets are passed at the descriptor numbers named in `VEGA_SHARD_FDS`. On Darwin, only those and stdio reach the shard (`POSIX_SPAWN_CLOEXEC_DEFAULT`).
- Signals: the shard starts with the signal mask from before the supervisor existed, and with SIGCHLD, SIGTERM, SIGINT and SIGHUP at their defaults.

## Listener modes

| `ShardListenerMode` | How it works | Default on |
|---|---|---|
| `.perShard` | Each shard binds its own `SO_REUSEPORT` socket, and the kernel hashes connections across them | Linux |
| `.shared` | The supervisor binds and listens once, before starting shards, and every shard accepts on that one socket | Darwin and others |

With `.perShard` and port 0, the supervisor holds a bound socket that isn't listening, so every shard gets the same port.

**Why shared on Darwin.** Darwin accepts `SO_REUSEPORT` on several TCP listeners but doesn't balance across them. Every connection goes to the most recently bound one. With 3 listeners on one port, 300 of 300 connections went to the newest, and the same happened after one was closed and bound again. A restarted shard would therefore take all the traffic from the others.

**Spread in shared mode.** Connections go to whichever shard is waiting in `accept` when they arrive. Measured on an M1 with 3 shards and 300 connections:

| Client | Shard 0 | Shard 1 | Shard 2 |
|---|---|---|---|
| One connection at a time | 4 | 71 | 225 |
| 32 concurrent | 59 | 112 | 129 |

Under light, sequential load the spread follows whichever shard's worker wakes first. Under concurrent load every shard gets a share, and the busiest has about twice the share of the least busy. Shared mode balances by who is free, not by an even hash, which suits uneven request costs. On Linux, `.perShard` hashes connections evenly, and `.shared` also works if you prefer to balance by load.

## Signals

| Signal to the supervisor | What happens |
|---|---|
| SIGTERM or SIGINT | Stop: every shard gets SIGTERM, then SIGKILL after `shutdownGracePeriod`. A second SIGTERM or SIGINT sends SIGKILL at once. The supervisor exits 0. |
| SIGHUP | Rolling restart: one shard at a time is sent SIGTERM, and once it has exited a new one starts before the next is stopped. The other shards keep serving. |
| SIGCHLD | Used internally to notice shard exits. |

The supervisor takes its signals synchronously:

- On Linux it blocks them and collects them with `sigtimedwait`.
- On Darwin it sets SIGTERM, SIGINT and SIGHUP to ignored and reads them from a kqueue (`EVFILT_SIGNAL`), which still reports ignored signals. SIGCHLD stays at its default there.

**When the supervisor dies.** Each shard ends with it, by getting SIGTERM:

- On Linux through `PR_SET_PDEATHSIG`, which an exec'd shard sets for itself.
- On Darwin through a small thread in each shard that waits on its own kqueue for the supervisor's exit (`EVFILT_PROC`, `NOTE_EXIT`).

A shard whose supervisor is already gone when it starts exits at once. After a SIGKILL of the supervisor, all shards were gone within a second on both launch modes.

## Restart policy

- **Crashed shards are restarted.** A shard crashed if it died from a signal or exited non-zero. One that exits 0 has finished and is not restarted.
- **Backoff.** The first crash restarts the shard at once. If it keeps crashing within a second of starting, the delay goes 100 ms, 200 ms, 400 ms and so on, up to 5 s. A shard that lives longer than a second resets the count.
- **Turning restarts off.** With `restartCrashed = false`, a crashed shard stays down and the supervisor exits 1 once every shard has ended.
- **Exit status.** The supervisor exits 0 after a stop signal or when every shard finished cleanly, and 1 when a crashed shard was not restarted.
- **Events.** `onEvent` reports each step:
  - `started(shard:pid:)`;
  - `exited(shard:pid:code:signal:)`;
  - `restarting(shard:after:)`;
  - `stopping(signal:)`;
  - `reloading`.

  It runs in the supervisor, which is single-threaded, so keep it short and don't start tasks or threads in it.

## Checking it

`Benchmarks/vega-shard-check` runs a 3-shard server end to end:

1. Every shard serves.
2. A crashed shard comes back and the others carry on.
3. SIGHUP replaces every shard.
4. SIGTERM stops everything with exit 0.

`VEGA_SHARD_LAUNCH=fork|exec` and `VEGA_SHARD_LISTENERS=shared|perShard` override the defaults:

- Linux passes all four combinations on both drivers.
- On Darwin, the default (exec with a shared listener) passes. Per-shard listeners fail, for the reason above.
