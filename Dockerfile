FROM rust:1.96.1-bookworm AS builder

WORKDIR /usr/src/harness
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime

RUN mkdir /data \
    && chown nobody:nogroup /data

COPY --from=builder /usr/src/harness/target/release/dappnode-package-harness /usr/local/bin/dappnode-package-harness
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER nobody:nogroup
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/dappnode-package-harness"]
