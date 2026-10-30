# CloudFront bug-host front

Same idea as the Cloudflare bug host (`BUG_HOST` in `generate_v2ray_links.py`), but on
AWS CloudFront: the client dials a zero-rated host that sits on CloudFront, and CloudFront
forwards the request to our Xray node.

```
client --TLS(SNI=dxxxx.cloudfront.net)--> bug-host IP (CloudFront edge)
       --> CloudFront distribution --HTTPS--> v2ray.ufone-claim.site (CF tunnel / VPS) --> Xray
```

## What is needed

| Item | Notes |
|---|---|
| AWS account | Needs a credit/debit card at sign-up. Free tier: 1 TB/month out + 10M requests. |
| IAM access key | `aws configure` with CloudFront + CloudFormation permissions. |
| Stable origin hostname | Default `live_domain_v2ray.txt` (`v2ray.ufone-claim.site`, named tunnel). Never a `trycloudflare.com` URL, because it changes every run. The Jeddah VPS domain also works. |
| CloudFront bug host | A zero-rated host on the carrier whose IPs are in AWS's CLOUDFRONT ranges. Check with `cf_check.py`. |

## The catch (read before spending time)

Since 2024 CloudFront **rejects domain fronting**: the TLS SNI must belong to the same
account as the Host. So:

- address = bug host (only the **IP** is borrowed)
- SNI = Host = **our** `dxxxx.cloudfront.net`

This only gives free data if the carrier zero-rates by **destination IP / DNS**. A carrier
that zero-rates by **SNI string** sees `dxxxx.cloudfront.net` and bills it, and there's no
fix on CloudFront for that. Test with a few MB and check the balance.

## Steps

```bash
# 1. Create the distribution (stack in us-east-1, ~5-10 min first time)
bash cloudfront/deploy.sh                       # origin = live_domain_v2ray.txt
bash cloudfront/deploy.sh jedah.talhacodes.site # or the VPS (needs a valid cert, else add http-only)

# 2. Find / verify a bug host (resolves to CloudFront + reaches our origin through it)
python3 cloudfront/cf_check.py --dist "$(cat cloudfront/domain.txt)" candidate1.com candidate2.com

# 3. Client links
CF_BUG_HOST=candidate1.com V2RAY_UUID=... python3 cloudfront/cf_links.py
```

Manual equivalent of step 2:
`curl -v --resolve dxxxx.cloudfront.net:443:<bug-ip> https://dxxxx.cloudfront.net/xh`.
A reply with `Server: cloudflare` (or from Xray) is good. `Server: CloudFront` 403/421
means CloudFront rejected the request, and 502/504 means the origin is down.

## Distribution settings (in `cloudfront.yaml`) and why

- **CachingDisabled** cache policy: this is a proxy, nothing should be cached.
- **All methods** allowed: XHTTP `packet-up` uploads with POST.
- **AllViewerExceptHostHeader** origin request policy: forwards query (`?ed=2048`) and
  headers but sets Host = origin, so the Cloudflare tunnel ingress / vhost matches.
- **OriginReadTimeout 60**: the XHTTP downlink is a long GET; 60 s is the max without an
  AWS quota request. Idle streams past that get cut and the client reconnects.
- WebSocket needs no setting; CloudFront passes upgrades through.
- Xray paths are unchanged (`/xh` XHTTP, `/vless` and `/vmess` WS, see `setup_v2ray.sh`),
  so the server needs **no changes**. CloudFront is just another front for the same node.

## Files

- `cloudfront.yaml`: CloudFormation template (the distribution).
- `deploy.sh`: deploys the stack and writes `domain.txt`.
- `cf_check.py`: CloudFront-range check + fronted probe for candidate bug hosts.
- `cf_links.py`: VLESS XHTTP / VLESS WS / VMess WS links (reuses `generate_v2ray_links.py`).
- `domain.txt`: created by `deploy.sh`, holds our `dxxxx.cloudfront.net`.

## Teardown

`aws cloudformation delete-stack --region us-east-1 --stack-name xray-cloudfront`
(the distribution is disabled first automatically; it takes ~15 min).
