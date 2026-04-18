FROM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/checkpoint-ldap-agent .

FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 1000 -m checkpoint
COPY --from=builder /app/checkpoint-ldap-agent /usr/local/bin/
EXPOSE 389 636 9090
HEALTHCHECK --interval=30s --timeout=3s CMD /usr/local/bin/checkpoint-ldap-agent -healthcheck
USER checkpoint
CMD ["checkpoint-ldap-agent"]
