# Dockerfile format ripped from here: https://shaneutt.com/blog/rust-fast-small-docker-image-builds/
# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------

FROM rust:latest as cargo-build

RUN apt-get update

RUN apt-get install musl-tools -y

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/main

COPY Cargo.lock Cargo.lock
COPY Cargo.toml Cargo.toml

RUN mkdir src/

RUN echo "fn main() {println!(\"if you see this, the build cache was invalidated\")}" > src/main.rs

RUN cargo build --release --target=x86_64-unknown-linux-musl

RUN rm -f target/x86_64-unknown-linux-musl/release/deps/snark-setup-operator*

COPY src ./src
COPY LICENSE .
COPY Cargo.lock .
COPY README.md .

RUN cargo build --release --bin generate --target=x86_64-unknown-linux-musl
RUN cargo build --release --bin contribute --target=x86_64-unknown-linux-musl
RUN cargo build --release --bin control --target=x86_64-unknown-linux-musl
RUN cargo build --release --bin monitor --target=x86_64-unknown-linux-musl
RUN cargo build --release --bin new_ceremony --target=x86_64-unknown-linux-musl
RUN cargo build --release --bin verify_transcript --target=x86_64-unknown-linux-musl

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------

FROM alpine:3.15

RUN addgroup -g 1000 main

RUN adduser -D -s /bin/sh -u 1000 -G main main

WORKDIR /home/main/bin/

COPY --from=cargo-build /usr/src/main/target/x86_64-unknown-linux-musl/release/contribute .
COPY --from=cargo-build /usr/src/main/target/x86_64-unknown-linux-musl/release/generate .
COPY --from=cargo-build /usr/src/main/target/x86_64-unknown-linux-musl/release/control .
COPY --from=cargo-build /usr/src/main/target/x86_64-unknown-linux-musl/release/monitor .
COPY --from=cargo-build /usr/src/main/target/x86_64-unknown-linux-musl/release/new_ceremony .
COPY --from=cargo-build /usr/src/main/target/x86_64-unknown-linux-musl/release/verify_transcript .

RUN chown main:main contribute
RUN chown main:main generate
RUN chown main:main control
RUN chown main:main monitor
RUN chown main:main new_ceremony
RUN chown main:main verify_transcript
RUN chown main:main .

USER main

CMD ["./contribute"]
