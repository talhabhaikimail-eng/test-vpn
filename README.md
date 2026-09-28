# Test V2Ray GitHub Actions Setup

This repository contains a GitHub Actions workflow to set up and test a temporary V2Ray proxy using Docker and Ngrok.

## Prerequisites
Before running the workflow, make sure you configure the following repository secret in GitHub:
- `NGROK_AUTH_TOKEN`: Your Ngrok authentication token from [dashboard.ngrok.com](https://dashboard.ngrok.com).

## Configuration
- **Ngrok Domain**: `wand-dedicate-output.ngrok-free.dev`
- **Secret**: `NGROK_AUTH_TOKEN` (configured in repository secrets)

## Usage
1. Go to the **Actions** tab in your GitHub repository.
2. Select **Test V2Ray Setup**.
3. Click **Run workflow** (via `workflow_dispatch`).
4. View the run logs to retrieve the connection details and credentials.
