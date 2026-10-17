# The Linux CI image: Swift 6.3.3 with what Vega's C targets link.
FROM swift:6.3.3-noble
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl-dev zlib1g-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
