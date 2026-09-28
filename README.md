# Test V2Ray GitHub Actions Setup

This repository contains a GitHub Actions workflow to set up and test a temporary V2Ray proxy using Docker and Ngrok.

## Prerequisites
Before running the workflow, make sure you configure the following repository secret in GitHub:
- `NGROK_AUTH_TOKEN`: Your Ngrok authentication token from [dashboard.ngrok.com](https://dashboard.ngrok.com).

## Configuration
- **Ngrok Domain**: `wand-dedicate-output.ngrok-free.dev`
- **Secret**: `NGROK_AUTH_TOKEN` (configured in repository secrets)
- **Default UUID**: `2fadaa2a-e7f6-4efe-8b6e-ccad3787feae`
- **Keep-Alive Duration**: Up to 6 hours (configurable via `duration_hours` input)

## Client Settings (v2rayN, v2rayNG, Nekoray, Shadowrocket, Clash)
- **Protocol**: `VMess`
- **Address**: `wand-dedicate-output.ngrok-free.dev`
- **Port**: `443`
- **UUID**: `2fadaa2a-e7f6-4efe-8b6e-ccad3787feae`
- **AlterID**: `0`
- **Security / Cipher**: `auto` (or `chacha20-poly1305`)
- **Transport / Network**: `ws` (WebSocket)
- **TLS**: `TLS` enabled (ServerName/SNI: `wand-dedicate-output.ngrok-free.dev`)
- **Path**: `/v2ray`

### Critical Custom Header (Ngrok Free Tier Requirement)
Ngrok free tier displays an interstitial warning page which prevents the WebSocket handshake unless you add this HTTP header under your client's WebSocket settings:
- **Header Key**: `ngrok-skip-browser-warning`
- **Header Value**: `1`
- **Host**: `wand-dedicate-output.ngrok-free.dev`

## Usage
1. Go to the **Actions** tab in your GitHub repository.
2. Select **Test V2Ray Setup**.
3. Click **Run workflow** (via `workflow_dispatch` or push).
4. View the run logs to retrieve the connection details and credentials.

