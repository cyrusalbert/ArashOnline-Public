# arashonline

Python + GitHub Actions repo that builds a tested v2ray subscription (`arashonline.txt`) every 12 hours.

## Setup
1. Create a GitHub repo and upload these files.
2. Put your subscription links in `sourcelist.txt` (one per line).
3. Repo **Settings → Actions → General → Workflow permissions** → *Read and write*.
4. Run **Actions → Update configs → Run workflow** once; after that it runs every 12 h.

Subscription URL (raw): `https://raw.githubusercontent.com/cyrusalbert/ArashOnline-Public/main/arashonline.txt#ArashOnline-Public`

## Pipeline
1. Fetch + decode all subscriptions (vmess / vless / trojan / ss), dedupe.
2. Alive test through Xray-core: `https://www.gstatic.com/generate_204`, dead if > 2000 ms.
3. Sort by ping (lowest first) → rank number.
4. Download speed test on the best `MAX_CONFIGS` (default 300) → final order is highest Mbps first.
5. Remark: `rank | 🇩🇪 | ip | 123ms | 45.6Mbps`

## Options (env vars)
`MAX_CONFIGS` (300), `SPEED_URL`, `ALLOW_INSECURE=1` (accept self-signed TLS), `XRAY_PATH`.

Local run: install [Xray-core](https://github.com/XTLS/Xray-core/releases), then `pip install -r requirements.txt && python main.py`.
