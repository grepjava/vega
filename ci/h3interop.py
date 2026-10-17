#!/usr/bin/env python3
"""HTTP/3 interop between Vega and aioquic, which share no code.

    python3 ci/h3interop.py BIN

BIN is vega-conformance. Two directions:
  * aioquic's client against `BIN h3`: GETs, a POST with a body larger than
    the stream windows, and many requests at once on one connection;
  * `BIN h3get` against an aioquic server: GET and a large POST.
Every response body is "METHOD TARGET BODY_LENGTH". Exits non-zero on any
failure. Needs aioquic: pip install aioquic.
"""

import asyncio
import os
import ssl
import subprocess
import sys
import tempfile
import time

from aioquic.asyncio import serve
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated

BIN = sys.argv[1]
PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok    {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name} {detail}")


# ---- aioquic client -> Vega server ------------------------------------------

class Client(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3 = H3Connection(self._quic)
        self.waiting = {}

    async def request(self, method, path, body=b""):
        sid = self._quic.get_next_available_stream_id()
        headers = [(b":method", method.encode()), (b":scheme", b"https"),
                   (b":authority", b"localhost"), (b":path", path.encode())]
        self.h3.send_headers(sid, headers, end_stream=not body)
        if body:
            self.h3.send_data(sid, body, end_stream=True)
        fut = asyncio.get_running_loop().create_future()
        self.waiting[sid] = [fut, None, b""]
        self.transmit()
        return await asyncio.wait_for(fut, 10)

    def quic_event_received(self, event):
        for e in self.h3.handle_event(event):
            w = self.waiting.get(e.stream_id)
            if not w:
                continue
            if isinstance(e, HeadersReceived):
                w[1] = dict(e.headers)
            elif isinstance(e, DataReceived):
                w[2] += e.data
            if getattr(e, "stream_ended", False) and not w[0].done():
                w[0].set_result((int(w[1][b":status"]), w[2]))


async def aioquic_client(port):
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name="localhost")
    config.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=config, create_protocol=Client) as c:
        status, body = await c.request("GET", "/hello")
        check("aioquic GET", status == 200 and body == b"GET /hello 0", (status, body))
        big = os.urandom(3 << 20)
        status, body = await c.request("POST", "/upload", big)
        check("aioquic POST 3 MiB", status == 200 and body == f"POST /upload {len(big)}".encode(), (status, body))
        results = await asyncio.gather(*(c.request("GET", f"/item/{i}") for i in range(64)))
        check("aioquic 64 at once", all(r == (200, f"GET /item/{i} 0".encode()) for i, r in enumerate(results)))


# ---- Vega client -> aioquic server -------------------------------------------

class Server(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3 = None
        self.requests = {}

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.h3 = H3Connection(self._quic)
        if not self.h3:
            return
        for e in self.h3.handle_event(event):
            if isinstance(e, HeadersReceived):
                h = dict(e.headers)
                self.requests[e.stream_id] = [h[b":method"].decode(), h[b":path"].decode(), 0]
            elif isinstance(e, DataReceived):
                self.requests[e.stream_id][2] += len(e.data)
            if getattr(e, "stream_ended", False):
                m, p, n = self.requests.pop(e.stream_id)
                body = f"{m} {p} {n}".encode()
                self.h3.send_headers(e.stream_id, [(b":status", b"200"), (b"content-length", str(len(body)).encode())])
                self.h3.send_data(e.stream_id, body, end_stream=True)
                self.transmit()


def vega_client(port):
    for path, size in [("/hello", 0), ("/upload", 2 << 20)]:
        out = subprocess.run([BIN, "h3get", "127.0.0.1", str(port), path, str(size)],
                             capture_output=True, text=True, timeout=30)
        want = f"{'POST' if size else 'GET'} {path} {size}"
        check(f"Vega client {want}", out.returncode == 0 and "status 200" in out.stdout and want in out.stdout,
              out.stdout + out.stderr)


async def main():
    # Vega's server.
    server = subprocess.Popen([BIN, "h3", "4433"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        time.sleep(1)
        await aioquic_client(4433)
    except Exception as e:
        check("aioquic client run", False, repr(e))
    finally:
        server.kill()

    # aioquic's server, with a certificate of its own.
    with tempfile.TemporaryDirectory() as d:
        cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-keyout", key, "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        config.load_cert_chain(cert, key)
        quic = await serve("127.0.0.1", 4434, configuration=config, create_protocol=Server)
        try:
            await asyncio.get_running_loop().run_in_executor(None, vega_client, 4434)
        finally:
            quic.close()

    print(f"{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


asyncio.run(main())
