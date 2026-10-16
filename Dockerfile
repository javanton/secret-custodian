# syntax=docker/dockerfile:1
FROM rust:1-slim-bookworm AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p sg --locked

FROM debian:bookworm-slim
# ca-certificates: system roots for upstream TLS. The /data directory must be 0700: the admin
# socket lives there and `sg serve` refuses a socket in a directory others can enter.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 sg \
    && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin sg \
    && mkdir /data && chown 10001:10001 /data && chmod 0700 /data
COPY --from=build /src/target/release/sg /usr/local/bin/sg
USER 10001:10001
# Lets `docker exec <container> sg secret ls` find the admin socket without flags.
ENV SG_SOCKET=/data/sg.sock
VOLUME /data
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["sg", "--socket", "/data/sg.sock", "ca", "status"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["sg"]
# Key source: a file at /run/secrets/sg_key (mode 0400/0600, owned by uid 10001) or, alternatively,
# SG_MASTER_KEY in the environment (then override the command without --key-file).
CMD ["serve", "--data-dir", "/data", "--socket", "/data/sg.sock", "--key-file", "/run/secrets/sg_key", \
     "--proxy-bind", "0.0.0.0:8080", "--admin-bind", "0.0.0.0:9090"]
