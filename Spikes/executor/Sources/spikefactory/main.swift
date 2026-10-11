@_spi(ExperimentalCustomExecutors) import _Concurrency
@_spi(Vega) import SpikeCore
import Glibc

let shared = Pool(threads: 4)

/// SE-0463-style install: the runtime asks this factory for the default
/// (global) executor, so every unpreferenced task should land on `shared`.
struct VegaFactory: ExecutorFactory {
    static var mainExecutor: any MainExecutor { ForwardingMain() }
    static var defaultExecutor: any TaskExecutor { shared }
}

func checks() async {
    let plain = await Task { currentPoolWorker() }.value
    line("plain Task {} lands on pool", plain > 0, "worker \(plain)")
    let detached = await Task.detached { currentPoolWorker() }.value
    line("Task.detached lands on pool", detached > 0, "worker \(detached)")
    let before = shared.timedEnqueues.load(ordering: .relaxed)
    try? await Task.sleep(for: .milliseconds(5))
    line("Task.sleep (no preference) uses pool's SchedulingExecutor",
         shared.timedEnqueues.load(ordering: .relaxed) > before)
    line("Task.defaultExecutor is the pool", Task.defaultExecutor === shared)
    await probePlacement(pool: shared)
    await runBenches(pool: shared, label: "global = pool via factory")
}

@main
struct App {
    typealias DefaultExecutorFactory = VegaFactory

    // Synchronous main: install the factory explicitly before any task exists,
    // then hand the thread to the main executor.
    static func main() throws {
        let explicit = CommandLine.arguments.contains("--explicit")
        print("== spikefactory: \(explicit ? "_createExecutors(factory:) called explicitly" : "DefaultExecutorFactory typealias only")")
        if explicit { _createExecutors(factory: VegaFactory.self) }
        Task.detached { await checks(); exit(0) }
        try MainActor.executor.run()
    }
}
