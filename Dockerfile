FROM rust:1-bookworm as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && \
    echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs
RUN cargo build --release
RUN rm -rf src && \
    rm -f target/release/deps/clipboard_server*

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/clipboard_server /app/server

# 暴露端口 (这就仅仅是个文档说明)
EXPOSE 3000

CMD ["./server"]