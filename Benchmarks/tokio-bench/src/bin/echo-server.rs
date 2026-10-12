//! TCP echo server on Tokio's multi-threaded runtime: the reference for
//! vega-echo. One task per connection, a 4 KiB buffer, echo until EOF.
//!
//!   echo-server [--port 7000] [--workers N]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn main() {
    let mut port = 7000u16;
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
        let listener = TcpListener::bind(("0.0.0.0", port)).await.unwrap();
        eprintln!("tokio echo: port {port}, {workers} workers");
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.set_nodelay(true).unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
}
