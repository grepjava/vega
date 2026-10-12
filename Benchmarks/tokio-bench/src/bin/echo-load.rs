//! Closed-loop TCP echo load: each connection sends a message, waits for all
//! of it to come back, and repeats. The same client drives every server, so
//! only the server differs between runs.
//!
//!   echo-load [--addr 127.0.0.1:7000] [--conns 64] [--size 64]
//!             [--secs 10] [--warmup 2] [--threads 4]
//!
//! Prints requests per second and round-trip latency percentiles.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn main() {
    let mut addr = "127.0.0.1:7000".to_string();
    let (mut conns, mut size, mut secs, mut warmup, mut threads) = (64usize, 64usize, 10u64, 2u64, 4usize);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut v = || args.next().unwrap();
        match a.as_str() {
            "--addr" => addr = v(),
            "--conns" => conns = v().parse().unwrap(),
            "--size" => size = v().parse().unwrap(),
            "--secs" => secs = v().parse().unwrap(),
            "--warmup" => warmup = v().parse().unwrap(),
            "--threads" => threads = v().parse().unwrap(),
            other => panic!("unknown option {other}"),
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap();

    let measuring = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let samples: Vec<Vec<u32>> = rt.block_on(async {
        let mut handles = Vec::with_capacity(conns);
        for _ in 0..conns {
            let addr = addr.clone();
            let (measuring, stop) = (measuring.clone(), stop.clone());
            handles.push(tokio::spawn(async move {
                let mut sock = TcpStream::connect(&addr).await.expect("connect");
                sock.set_nodelay(true).unwrap();
                let msg = vec![b'x'; size];
                let mut back = vec![0u8; size];
                let mut lat = Vec::with_capacity(1 << 16);
                while !stop.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    sock.write_all(&msg).await.expect("write");
                    sock.read_exact(&mut back).await.expect("read");
                    if measuring.load(Ordering::Relaxed) {
                        lat.push(t.elapsed().as_nanos().min(u32::MAX as u128) as u32);
                    }
                }
                lat
            }));
        }
        tokio::time::sleep(Duration::from_secs(warmup)).await;
        measuring.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(secs)).await;
        measuring.store(false, Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
        let mut all = Vec::new();
        for h in handles {
            all.push(h.await.unwrap());
        }
        all
    });

    let mut lat: Vec<u32> = samples.into_iter().flatten().collect();
    lat.sort_unstable();
    let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)] as f64 / 1000.0;
    println!(
        "conns {conns:>5}  size {size:>5}  req/s {:>10.0}  p50 {:>8.1} us  p99 {:>8.1} us  p99.9 {:>8.1} us",
        lat.len() as f64 / secs as f64,
        pct(0.50),
        pct(0.99),
        pct(0.999)
    );
}
