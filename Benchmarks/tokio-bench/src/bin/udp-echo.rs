//! UDP echo server on Tokio: the reference for vega-udp. One socket per
//! worker on consecutive ports from --port, each served by one task that
//! sends every datagram back to its sender (recv_from / send_to, as plain
//! Tokio code does).
//!
//!   udp-echo [--port 7100] [--workers N]
use std::net::SocketAddr;
use tokio::net::UdpSocket;

fn main() {
    let mut port = 7100u16;
    let mut workers = std::thread::available_parallelism().unwrap().get();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => port = args.next().unwrap().parse().unwrap(),
            "--workers" => workers = args.next().unwrap().parse().unwrap(),
            other => panic!("unknown option {other}"),
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async move {
        let mut tasks = Vec::new();
        for i in 0..workers {
            let addr: SocketAddr = format!("127.0.0.1:{}", port as usize + i).parse().unwrap();
            let sock = UdpSocket::bind(addr).await.unwrap();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let (n, from) = sock.recv_from(&mut buf).await.unwrap();
                    let _ = sock.send_to(&buf[..n], from).await;
                }
            }));
        }
        eprintln!("tokio udp echo: port {port}, {workers} workers");
        for t in tasks {
            t.await.unwrap();
        }
    });
}
