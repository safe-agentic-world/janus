FROM golang:1.24.13-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/nomos ./cmd/nomos

FROM alpine:3.20
WORKDIR /demo
COPY --from=build /out/nomos /usr/local/bin/nomos
COPY examples /demo/examples
COPY policies /demo/policies
EXPOSE 8080
CMD ["nomos", "serve", "-c", "/demo/examples/quickstart/config.quickstart.json", "-p", "/demo/policies/safe-dev-hardened.yaml"]
