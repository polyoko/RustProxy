FROM rust:1-slim-bookworm AS build
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
  && printf 'fn main() {}\n' > src/main.rs \
  && printf '' > src/lib.rs \
  && cargo build --release --locked

COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /app/target/release/rust_proxy /usr/local/bin/rust_proxy
EXPOSE 8080 8081
ENV RUST_PROXY_API_BIND=0.0.0.0
ENTRYPOINT ["sh", "-ec", "exec /usr/local/bin/rust_proxy server -c 8080 -a 8081 -p \"$RUST_PROXY_PASSWORD\" --admin-password \"${RUST_PROXY_ADMIN_PASSWORD:?RUST_PROXY_ADMIN_PASSWORD is required}\""]
