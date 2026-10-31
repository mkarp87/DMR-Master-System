FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo test --workspace && cargo build --release -p dmr-master

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home dmrmaster
COPY --from=build /src/target/release/dmr-master /usr/local/bin/dmr-master
COPY fixtures /opt/dmr-master/fixtures
USER dmrmaster
WORKDIR /opt/dmr-master
ENV RUST_LOG=info
EXPOSE 8080/tcp
ENTRYPOINT ["/usr/local/bin/dmr-master"]
