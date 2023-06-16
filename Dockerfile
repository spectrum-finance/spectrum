FROM rust:slim AS builder

RUN apt update && apt-get install -y clang
RUN update-ca-certificates

WORKDIR /usr/src/app

# copy entire workspace
COPY . .

RUN cargo build  --release


FROM debian:bullseye-slim
COPY --from=builder /usr/src/app/target/release/spectrum-node ./
CMD [ "./spectrum-node" ]