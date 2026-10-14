#!/bin/sh
# Starts V2Ray Core + proxy_v2ray. If either process dies the container exits,
# so Render restarts it (no half-alive node).
set -eu

: "${V2RAY_UUID:?V2RAY_UUID env var is required (use the same UUID as your client links)}"
PORT="${PORT:-10000}"
NODE_NAME="${NODE_NAME:-V2Ray SG (Render)}"
CONFIG=/tmp/v2ray_config.json

sed "s/__UUID__/${V2RAY_UUID}/g" /etc/v2ray/config.tmpl.json > "$CONFIG"
v2ray test -c "$CONFIG" -format json > /dev/null

v2ray run -c "$CONFIG" -format json &
V2_PID=$!

# Give the inbounds a moment to bind before accepting traffic.
sleep 1
kill -0 "$V2_PID"

# Web panel (config links + speed test) only when a password is set: it shows the UUID.
UI_PID=""
HTTP_ARG=""
if [ -n "${UI_PASSWORD:-}" ]; then
  v2ray_ui --listen 127.0.0.1:10090 &
  UI_PID=$!
  HTTP_ARG="--http 127.0.0.1:10090"
else
  echo "[entrypoint] UI_PASSWORD not set; web panel disabled" >&2
fi

# shellcheck disable=SC2086
proxy_v2ray --listen "0.0.0.0:${PORT}" --vless 127.0.0.1:10085 --vmess 127.0.0.1:10086 $HTTP_ARG --name "$NODE_NAME" &
PX_PID=$!

trap 'kill "$V2_PID" "$PX_PID" $UI_PID 2>/dev/null; exit 0' TERM INT

alive() {
  for pid in "$V2_PID" "$PX_PID" $UI_PID; do
    kill -0 "$pid" 2>/dev/null || return 1
  done
}
while alive; do
  sleep 2
done

echo "[entrypoint] a process exited; stopping container so Render restarts it" >&2
kill "$V2_PID" "$PX_PID" $UI_PID 2>/dev/null || true
exit 1
