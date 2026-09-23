FROM rust:1-slim-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /app/target/release/rust_proxy /usr/local/bin/rust_proxy
EXPOSE 8080 8081
ENTRYPOINT ["sh", "-c", "exec /usr/local/bin/rust_proxy server -c 8080 -a 8081 -p \"$RUST_PROXY_PASSWORD\""]
