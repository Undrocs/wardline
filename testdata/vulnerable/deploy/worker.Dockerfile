# Build stage uses a full toolchain image; the final stage never drops root.
FROM golang:1.23 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/worker ./cmd/worker

FROM debian:12-slim
COPY --from=build /out/worker /usr/local/bin/worker
ENTRYPOINT ["/usr/local/bin/worker"]
