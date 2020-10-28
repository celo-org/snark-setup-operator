# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------

FROM rust:latest as cargo-build

RUN apt-get update

RUN apt-get install musl-tools -y

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/main

COPY Cargo.toml Cargo.toml

RUN mkdir src/

RUN echo "fn main() {println!(\"if you see this, the build cache was invalidated\")}" > src/main.rs

RUN RUSTFLAGS=-Clinker=musl-gcc cargo build --release --target=x86_64-unknown-linux-musl

RUN rm -f target/x86_64-unknown-linux-musl/release/deps/snark-setup-operator*

COPY src .
COPY LICENSE .
COPY Cargo.lock .
COPY README.md .

RUN RUSTFLAGS=-Clinker=musl-gcc cargo build --release --target=x86_64-unknown-linux-musl

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------

FROM alpine:latest

RUN addgroup -g 1000 main

RUN adduser -D -s /bin/sh -u 1000 -G main main

WORKDIR /home/main/bin/

COPY --from=cargo-build /usr/src/main/target/x86_64-unknown-linux-musl/release/snark-setup-operator .

RUN chown main:main snark-setup-operator

USER main

CMD ["./snark-setup-operator"]