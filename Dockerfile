FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/blocks ./cmd/blocks
RUN mkdir -p /out/data/uploads

FROM alpine:latest AS certs
RUN apk add --no-cache ca-certificates

FROM scratch

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/blocks /app/blocks
COPY --from=builder /app/static /app/static
COPY --from=builder /out/data /app/data

WORKDIR /app

EXPOSE 8080

ENV BLOCKS_ENV=production

ENTRYPOINT ["/app/blocks"]
