FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/auth-server ./cmd/server

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/auth-server /app/auth-server
EXPOSE 8081
CMD ["/app/auth-server"]
