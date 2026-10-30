#!/usr/bin/env bash
# Create/update the CloudFront distribution and save its domain to cloudfront/domain.txt.
#   Prereqs: aws CLI v2, `aws configure` done (IAM user with CloudFront + CloudFormation access).
#   Usage:   bash cloudfront/deploy.sh [origin-domain] [https-only|http-only]
set -euo pipefail
cd "$(dirname "$0")"

ORIGIN="${1:-$(tr -d '\r' < ../live_domain_v2ray.txt | xargs)}"
PROTO="${2:-https-only}"
STACK="xray-cloudfront"

case "$ORIGIN" in
  *trycloudflare.com) echo "Refusing $ORIGIN: quick-tunnel URLs change every run; use a named tunnel or VPS domain." >&2; exit 1;;
esac

echo "Deploying $STACK (origin=$ORIGIN, $PROTO); first create takes ~5-10 min..."
# CloudFront is global; its CloudFormation stacks must live in us-east-1.
aws cloudformation deploy --region us-east-1 --stack-name "$STACK" \
  --template-file cloudfront.yaml \
  --parameter-overrides "OriginDomain=$ORIGIN" "OriginProtocol=$PROTO" \
  --no-fail-on-empty-changeset

DOMAIN=$(aws cloudformation describe-stacks --region us-east-1 --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='DistributionDomain'].OutputValue" --output text)
echo "$DOMAIN" > domain.txt
echo "CloudFront domain: $DOMAIN  (saved to cloudfront/domain.txt)"
echo "Next: python3 cloudfront/cf_check.py --dist $DOMAIN <bug-host>"
