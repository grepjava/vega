//! Closed-loop UDP load: each flow (its own connected socket and thread)
//! keeps `window` datagrams in flight against an echo server, sending more
//! as replies come back. Sends and receives go through sendmmsg/recvmmsg, up
//! to 64 a call, so the client isn't what limits a fast server (elsewhere,
//! macOS for one, they are loops of send/recv). The same client drives every
//! server.
//!
//!   udp-load [--addr 127.0.0.1:7100] [--ports 4] [--flows 4] [--size 64]
//!            [--window 256] [--secs 10] [--warmup 2]
//!
//! Flow i goes to the address's port + i % ports: the servers listen on
//! consecutive ports, one socket per worker.
//!
//! Prints replies per second. A datagram lost on the way (the server's
//! socket buffer overflowed) is noticed by a 20 ms receive timeout, which
//! refills the window.
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const CHUNK: usize = 64;

fn main() {
    let mut addr = "127.0.0.1:7100".to_string();
    let (mut flows, mut size, mut window, mut secs, mut warmup) = (4usize, 64usize, 256usize, 10u64, 2u64);
    let mut ports = 1usize;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut v = || args.next().unwrap();
        match a.as_str() {
            "--addr" => addr = v(),
            "--flows" => flows = v().parse().unwrap(),
            "--ports" => ports = v().parse().unwrap(),
            "--size" => size = v().parse().unwrap(),
            "--window" => window = v().parse().unwrap(),
            "--secs" => secs = v().parse().unwrap(),
            "--warmup" => warmup = v().parse().unwrap(),
            other => panic!("unknown option {other}"),
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let received: Arc<Vec<AtomicU64>> = Arc::new((0..flows).map(|_| AtomicU64::new(0)).collect());
    let lost = Arc::new(AtomicU64::new(0));
    let mut threads = Vec::new();
    for f in 0..flows {
        let mut addr: std::net::SocketAddr = addr.parse().unwrap();
        addr.set_port(addr.port() + (f % ports) as u16);
        let (stop, received, lost) = (stop.clone(), received.clone(), lost.clone());
        threads.push(std::thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.connect(&addr).unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            run_flow(sock.as_raw_fd(), size, window, &stop, &received[f], &lost);
        }));
    }

    std::thread::sleep(Duration::from_secs(warmup));
    let before: u64 = received.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    let lost_before = lost.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_secs(secs));
    let after: u64 = received.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    let lost_after = lost.load(Ordering::Relaxed);
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        t.join().unwrap();
    }
    let pps = (after - before) as f64 / secs as f64;
    println!(
        "flows {flows:>3}  size {size:>5}  window {window:>4}  pps {pps:>10.0}  Mbit/s {:>7.0}  refills {}",
        pps * size as f64 * 8.0 / 1e6,
        lost_after - lost_before
    );
}

#[cfg(target_os = "linux")]
fn run_flow(fd: i32, size: usize, window: usize, stop: &AtomicBool, received: &AtomicU64, lost: &AtomicU64) {
    let payload = vec![b'u'; size];
    let mut recv_bufs = vec![0u8; CHUNK * 2048];
    unsafe {
        let mut send_iov: Vec<libc::iovec> = (0..CHUNK)
            .map(|_| libc::iovec { iov_base: payload.as_ptr() as *mut _, iov_len: size })
            .collect();
        let mut send_hdrs: Vec<libc::mmsghdr> = (0..CHUNK)
            .map(|i| {
                let mut h: libc::mmsghdr = std::mem::zeroed();
                h.msg_hdr.msg_iov = &mut send_iov[i];
                h.msg_hdr.msg_iovlen = 1;
                h
            })
            .collect();
        let mut recv_iov: Vec<libc::iovec> = (0..CHUNK)
            .map(|i| libc::iovec { iov_base: recv_bufs.as_mut_ptr().add(i * 2048) as *mut _, iov_len: 2048 })
            .collect();
        let mut recv_hdrs: Vec<libc::mmsghdr> = (0..CHUNK)
            .map(|i| {
                let mut h: libc::mmsghdr = std::mem::zeroed();
                h.msg_hdr.msg_iov = &mut recv_iov[i];
                h.msg_hdr.msg_iovlen = 1;
                h
            })
            .collect();

        let mut in_flight = 0usize;
        let mut total = 0u64;
        while !stop.load(Ordering::Relaxed) {
            while in_flight < window {
                let k = (window - in_flight).min(CHUNK);
                let n = libc::sendmmsg(fd, send_hdrs.as_mut_ptr(), k as u32, 0);
                if n <= 0 {
                    break;
                }
                in_flight += n as usize;
            }
            let n = libc::recvmmsg(fd, recv_hdrs.as_mut_ptr(), CHUNK as u32, libc::MSG_WAITFORONE, std::ptr::null_mut());
            if n > 0 {
                in_flight = in_flight.saturating_sub(n as usize);
                total += n as u64;
                received.store(total, Ordering::Relaxed);
            } else {
                // Timed out: what is still out was dropped. Refill.
                in_flight = 0;
                lost.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Without sendmmsg/recvmmsg: the same window, one datagram per call. The
/// first receive blocks (up to the 20 ms timeout), the rest of a chunk takes
/// only what is already queued, as MSG_WAITFORONE does.
#[cfg(not(target_os = "linux"))]
fn run_flow(fd: i32, size: usize, window: usize, stop: &AtomicBool, received: &AtomicU64, lost: &AtomicU64) {
    let payload = vec![b'u'; size];
    let mut buf = vec![0u8; 2048];
    let mut in_flight = 0usize;
    let mut total = 0u64;
    unsafe {
        while !stop.load(Ordering::Relaxed) {
            while in_flight < window {
                if libc::send(fd, payload.as_ptr() as *const _, size, 0) < 0 {
                    break; // ENOBUFS: the interface queue is full for now
                }
                in_flight += 1;
            }
            let mut n = 0usize;
            while n < CHUNK {
                let flags = if n == 0 { 0 } else { libc::MSG_DONTWAIT };
                if libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), flags) < 0 {
                    break;
                }
                n += 1;
            }
            if n > 0 {
                in_flight = in_flight.saturating_sub(n);
                total += n as u64;
                received.store(total, Ordering::Relaxed);
            } else {
                // Timed out: what is still out was dropped. Refill.
                in_flight = 0;
                lost.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
