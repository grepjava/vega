# The Linux CI image: Swift 6.3.3 with what Vega's C targets link, and
# aioquic for the HTTP/3 interop suite (ci/h3interop.py).
FROM swift:6.3.3-noble
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl-dev zlib1g-dev pkg-config openssl python3 python3-pip \
 && pip3 install --break-system-packages --no-cache-dir aioquic \
 && rm -rf /var/lib/apt/lists/*
