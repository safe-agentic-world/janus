FROM golang:1.25.8-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/nomos ./cmd/nomos

FROM alpine:3.20
WORKDIR /demo
COPY --from=build /out/nomos /usr/local/bin/nomos
COPY examples /demo/examples
COPY policies /demo/policies
EXPOSE 8080
CMD ["nomos", "serve", "-c", "/demo/examples/quickstart/config.quickstart.json", "-p", "/demo/policies/safe.yaml"]
