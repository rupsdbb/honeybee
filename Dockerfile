# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data honeybee \
 && mkdir /data && chown honeybee /data
COPY --from=build /src/target/release/honeybee /usr/local/bin/honeybee
USER honeybee
ENV HONEYBEE_LISTEN=0.0.0.0:8585 \
    HONEYBEE_DATA_DIR=/data
VOLUME /data
EXPOSE 8585
ENTRYPOINT ["/usr/local/bin/honeybee"]
