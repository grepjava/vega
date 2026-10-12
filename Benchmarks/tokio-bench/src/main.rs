//! The same scheduler and sync benchmarks as vega-bench, on Tokio's multi-threaded
//! runtime, so the numbers line up row for row.
//!
//!   tokio-bench [--workers N] [--runs N]
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Notify, Semaphore};

fn main() {
    let mut workers = std::thread::available_parallelism().unwrap().get();
    let mut runs = 7;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--workers" => workers = args.next().unwrap().parse().unwrap(),
            "--runs" => runs = args.next().unwrap().parse().unwrap(),
            other => panic!("unknown option {other}"),
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .build()
        .unwrap();

    println!("tokio-bench: {workers} workers, median of {runs} runs");
    println!("{:<16}{:>14}", "bench", "Tokio ns/op");

    let benches: [(&str, usize, fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>); 7] = [
        ("spawn_many", 100_000, || Box::pin(spawn_many())),
        ("chained_spawn", 10_000, || Box::pin(chained_spawn(10_000))),
        ("ping_pong", 100_000, || Box::pin(ping_pong())),
        ("yield_many", 100_000, || Box::pin(yield_many())),
        ("mpsc_ping_pong", 100_000, || Box::pin(mpsc_ping_pong())),
        ("mpsc_fan_in", 100_000, || Box::pin(mpsc_fan_in())),
        ("semaphore", 100_000, || Box::pin(semaphore())),
    ];
    for (name, ops, f) in benches {
        let mut samples: Vec<f64> = (0..runs)
            .map(|_| {
                rt.block_on(async {
                    // Run the body as a spawned task, like vega-bench runs it on a worker.
                    let t = Instant::now();
                    tokio::spawn(f()).await.unwrap();
                    t.elapsed().as_nanos() as f64 / ops as f64
                })
            })
            .collect();
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("{:<16}{:>14.1}", name, samples[runs / 2]);
    }
}

async fn spawn_many() {
    let handles: Vec<_> = (0..100_000).map(|_| tokio::spawn(async {})).collect();
    for h in handles {
        h.await.unwrap();
    }
}

fn chained_spawn(n: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        if n > 0 {
            tokio::spawn(chained_spawn(n - 1)).await.unwrap();
        }
    })
}

async fn ping_pong() {
    let a = Arc::new(Notify::new());
    let b = Arc::new(Notify::new());
    let (a2, b2) = (a.clone(), b.clone());
    let t1 = tokio::spawn(async move {
        for _ in 0..100_000 {
            a2.notified().await;
            b2.notify_one();
        }
    });
    let t2 = tokio::spawn(async move {
        for _ in 0..100_000 {
            a.notify_one();
            b.notified().await;
        }
    });
    t1.await.unwrap();
    t2.await.unwrap();
}

async fn yield_many() {
    let handles: Vec<_> = (0..200)
        .map(|_| {
            tokio::spawn(async {
                for _ in 0..500 {
                    tokio::task::yield_now().await;
                }
            })
        })
        .collect();
    for h in handles {
        h.await.unwrap();
    }
}

async fn mpsc_ping_pong() {
    let (tx1, mut rx1) = mpsc::channel::<usize>(1);
    let (tx2, mut rx2) = mpsc::channel::<usize>(1);
    let echo = tokio::spawn(async move {
        while let Some(v) = rx1.recv().await {
            if tx2.send(v).await.is_err() {
                break;
            }
        }
    });
    for i in 0..100_000 {
        tx1.send(i).await.unwrap();
        rx2.recv().await.unwrap();
    }
    drop(tx1);
    echo.await.unwrap();
}

async fn mpsc_fan_in() {
    let (tx, mut rx) = mpsc::channel::<usize>(1024);
    for _ in 0..8 {
        let tx = tx.clone();
        tokio::spawn(async move {
            for i in 0..12_500 {
                tx.send(i).await.unwrap();
            }
        });
    }
    drop(tx);
    let mut n = 0;
    while rx.recv().await.is_some() {
        n += 1;
    }
    assert_eq!(n, 100_000);
}

async fn semaphore() {
    let sem = Arc::new(Semaphore::new(2));
    let handles: Vec<_> = (0..200)
        .map(|_| {
            let sem = sem.clone();
            tokio::spawn(async move {
                for _ in 0..500 {
                    let _permit = sem.acquire().await.unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.await.unwrap();
    }
}
