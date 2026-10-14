# V2Ray (VLESS + VMess over WS) node for Render — same stack as the GitHub Actions node,
# minus cloudflared: Render terminates TLS and forwards WebSockets to $PORT.
#
#   client --TLS--> Cloudflare edge (bug host) --> Render (Singapore) --> proxy_v2ray --> v2ray

# ── Build the Go path router / TCP tuner + web panel ──────────────────────────────────────
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY proxy_v2ray.go quickack_linux.go ./
COPY render/ui/main.go ./ui/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/proxy_v2ray proxy_v2ray.go quickack_linux.go \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/v2ray_ui ./ui/main.go

# ── Fetch official V2Ray Core (pinned) ────────────────────────────────────────
FROM alpine:3.20 AS v2ray
ARG V2RAY_VERSION=v5.53.0
RUN apk add --no-cache curl unzip \
 && curl -fsSL --retry 3 -o /tmp/v2ray.zip \
      "https://github.com/v2fly/v2ray-core/releases/download/${V2RAY_VERSION}/v2ray-linux-64.zip" \
 && unzip -q /tmp/v2ray.zip v2ray -d /out \
 && chmod +x /out/v2ray

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=v2ray /out/v2ray /usr/local/bin/v2ray
COPY --from=build /out/proxy_v2ray /usr/local/bin/proxy_v2ray
COPY --from=build /out/v2ray_ui /usr/local/bin/v2ray_ui
COPY render/ui/index.html /usr/share/v2ray-ui/index.html
COPY render/v2ray_config.tmpl.json /etc/v2ray/config.tmpl.json
COPY render/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER nobody
ENV PORT=10000
EXPOSE 10000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
