FROM golang:1.25.8-alpine AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/nomos ./cmd/nomos

FROM openpolicyagent/opa:latest-static AS runtime-opa
WORKDIR /app
COPY --from=builder /out/nomos /app/nomos
USER 65532:65532
ENTRYPOINT ["/app/nomos"]

FROM gcr.io/distroless/static:nonroot AS runtime
WORKDIR /app
COPY --from=builder /out/nomos /app/nomos
USER nonroot:nonroot
ENTRYPOINT ["/app/nomos"]
