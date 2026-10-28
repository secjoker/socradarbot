# ── 前端构建 ─────────────────────────────────────────────
FROM node:20-alpine AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ── 后端构建 ─────────────────────────────────────────────
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/socradarbot ./cmd/socradarbot

# ── 运行镜像 ─────────────────────────────────────────────
FROM alpine:3.20
RUN apk add --no-cache ca-certificates git tzdata \
    && adduser -D -u 10001 socradar \
    && mkdir -p /app/data && chown -R socradar:socradar /app
WORKDIR /app
COPY --from=build /out/socradarbot /app/socradarbot
COPY --from=web /src/web/dist /app/web/dist
COPY config.example.yaml /app/config.example.yaml
USER socradar
EXPOSE 8100
ENTRYPOINT ["/app/socradarbot", "-addr", "0.0.0.0:8100", "-web", "/app/web/dist"]
