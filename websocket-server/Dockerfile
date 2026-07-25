FROM rust:1.75 as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/rug-pull-websocket-server /app/rug-pull-websocket-server

EXPOSE 8080

CMD ["/app/rug-pull-websocket-server"]
