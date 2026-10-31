#!/usr/bin/env python3
"""
Fetch v2ray subscriptions -> alive test (gstatic) -> sort by ping (<=2000ms)
-> download speed test -> rename -> write arashonline.txt
Testing is done with a real Xray-core process (needs `xray` binary).
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, quote, unquote, urlsplit

import requests

SOURCE_FILE = "sourcelist.txt"
OUTPUT_FILE = "arashonline.txt"
XRAY = os.environ.get("XRAY_PATH") or shutil.which("xray") or "./xray"

PING_URL = "https://www.gstatic.com/generate_204"
SPEED_URL = os.environ.get("SPEED_URL", "https://speed.cloudflare.com/__down?bytes=10000000")
MAX_PING_MS = 2000
MAX_CONFIGS = int(os.environ.get("MAX_CONFIGS", "300"))   # best-by-ping configs that get speed-tested/kept
ALLOW_INSECURE = os.environ.get("ALLOW_INSECURE", "0") == "1"

PING_BATCH, PING_WORKERS = 150, 50
SPEED_BATCH, SPEED_WORKERS = 20, 4
SPEED_SECONDS = 8
BASE_PORT = 20000
SCHEMES = ("vmess://", "vless://", "trojan://", "ss://")


# ---------------------------------------------------------------- fetching
def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def fetch_links(url):
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        text = r.text.strip()
    except Exception as e:
        print(f"[!] {url}: {e}")
        return []
    if not text.startswith(SCHEMES):
        try:
            text = b64d(text)
        except Exception:
            pass
    links = [l.strip() for l in text.splitlines() if l.strip().startswith(SCHEMES)]
    print(f"[+] {url}: {len(links)} links")
    return links


# ----------------------------------------------------------------- parsing
def stream(p):
    net = p.get("net") or "tcp"
    net = {"h2": "http", "splithttp": "xhttp"}.get(net, net)
    host, path = p.get("host", ""), p.get("path", "")
    hosts = [h for h in host.split(",") if h]
    s = {"network": net}
    if net == "ws":
        s["wsSettings"] = {"path": path or "/", "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": p.get("serviceName") or path,
                             "multiMode": p.get("mode") == "multi"}
    elif net == "http":
        s["httpSettings"] = {"path": path or "/", "host": hosts}
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": path or "/", "host": host}
    elif net == "xhttp":
        s["xhttpSettings"] = {"path": path or "/", "host": host, "mode": p.get("mode") or "auto"}
    elif net == "kcp":
        k = {"header": {"type": p.get("type") or "none"}}
        if p.get("seed"):
            k["seed"] = p["seed"]
        s["kcpSettings"] = k
    elif net == "tcp" and p.get("type") == "http":
        s["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path or "/"], "headers": {"Host": hosts}}}}

    sec = p.get("security", "none")
    if sec == "tls":
        t = {"serverName": p.get("sni") or host}
        if ALLOW_INSECURE:
            t["allowInsecure"] = True
        if p.get("fp"):
            t["fingerprint"] = p["fp"]
        if p.get("alpn"):
            t["alpn"] = p["alpn"].split(",")
        s["security"], s["tlsSettings"] = "tls", t
    elif sec == "reality":
        s["security"] = "reality"
        s["realitySettings"] = {"serverName": p.get("sni", ""),
                                "fingerprint": p.get("fp") or "chrome",
                                "publicKey": p.get("pbk", ""), "shortId": p.get("sid", ""),
                                "spiderX": p.get("spx", "")}
    return s


def parse_vmess(link):
    d = json.loads(b64d(link[8:]))
    p = dict(net=d.get("net", "tcp"), security="tls" if d.get("tls") == "tls" else "none",
             host=d.get("host", ""), path=d.get("path", ""), serviceName=d.get("path", ""),
             sni=d.get("sni") or d.get("host", ""), fp=d.get("fp", ""),
             alpn=d.get("alpn", ""), type=d.get("type", "none"))
    out = {"protocol": "vmess", "settings": {"vnext": [{
        "address": d["add"], "port": int(d["port"]),
        "users": [{"id": d["id"], "alterId": int(d.get("aid", 0) or 0),
                   "security": d.get("scy") or "auto"}]}]},
        "streamSettings": stream(p)}
    key = json.dumps({k: v for k, v in d.items() if k != "ps"}, sort_keys=True)
    return {"proto": "vmess", "host": d["add"], "outbound": out, "key": key, "vmess": d, "link": link}


def parse_url_style(link):  # vless / trojan
    u = urlsplit(link)
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    proto, host, port = u.scheme, u.hostname, u.port
    secret = unquote(u.username or "")
    p = dict(net=q.get("type", "tcp"),
             security=q.get("security", "none" if proto == "vless" else "tls"),
             host=q.get("host", ""), path=q.get("path", ""), sni=q.get("sni") or q.get("peer", ""),
             fp=q.get("fp", ""), alpn=q.get("alpn", ""), pbk=q.get("pbk", ""), sid=q.get("sid", ""),
             spx=q.get("spx", ""), serviceName=q.get("serviceName", ""), mode=q.get("mode", ""),
             type=q.get("headerType", "none"), seed=q.get("seed", ""))
    if proto == "vless":
        user = {"id": secret, "encryption": "none"}
        if q.get("flow"):
            user["flow"] = q["flow"]
        out = {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}
    else:
        out = {"protocol": "trojan", "settings": {"servers": [{"address": host, "port": port, "password": secret}]}}
    out["streamSettings"] = stream(p)
    return {"proto": proto, "host": host, "outbound": out, "key": link.split("#")[0], "link": link}


def parse_ss(link):
    body = link[5:].split("#")[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = unquote(userinfo) if ":" in unquote(userinfo) else b64d(userinfo)
    else:
        userinfo, hostport = b64d(body).rsplit("@", 1)
    method, password = userinfo.split(":", 1)
    host, port = hostport.split("?")[0].rstrip("/").rsplit(":", 1)
    host = host.strip("[]")
    out = {"protocol": "shadowsocks", "settings": {"servers": [{
        "address": host, "port": int(port), "method": method, "password": password}]}}
    return {"proto": "ss", "host": host, "outbound": out, "key": link.split("#")[0], "link": link}


def parse(link):
    try:
        if link.startswith("vmess://"):
            return parse_vmess(link)
        if link.startswith("ss://"):
            return parse_ss(link)
        return parse_url_style(link)
    except Exception:
        return None


# ------------------------------------------------------------------ xray
def make_config(batch):
    inbounds, outbounds, rules = [], [], []
    for i, n in enumerate(batch):
        inbounds.append({"tag": f"in{i}", "listen": "127.0.0.1", "port": BASE_PORT + i,
                         "protocol": "http", "settings": {}})
        o = dict(n["outbound"])
        o["tag"] = f"out{i}"
        outbounds.append(o)
        rules.append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"})
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    return {"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


def start_xray(batch):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(make_config(batch), f)
    proc = subprocess.Popen([XRAY, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    last, deadline = BASE_PORT + len(batch) - 1, time.time() + 8
    try:
        while time.time() < deadline:
            if proc.poll() is not None:
                return None
            try:
                socket.create_connection(("127.0.0.1", last), 0.2).close()
                return proc
            except OSError:
                time.sleep(0.2)
        proc.kill()
        return None
    finally:
        os.remove(path)


def run_batches(nodes, size, fn, workers):
    """fn(node, port) -> dict or None. Returns [(node, result)]."""
    results = []

    def process(batch):
        proc = start_xray(batch)
        if proc is None:                      # a bad config broke the batch -> bisect
            if len(batch) > 1:
                mid = len(batch) // 2
                process(batch[:mid])
                process(batch[mid:])
            return
        try:
            with ThreadPoolExecutor(workers) as ex:
                outs = ex.map(lambda a: fn(*a), [(n, BASE_PORT + i) for i, n in enumerate(batch)])
                for n, r in zip(batch, outs):
                    if r:
                        results.append((n, r))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    for i in range(0, len(nodes), size):
        process(nodes[i:i + size])
        print(f"    {min(i + size, len(nodes))}/{len(nodes)} done")
    return results


def proxies_for(port):
    u = f"http://127.0.0.1:{port}"
    return {"http": u, "https": u}


def ping_test(node, port):
    best = None
    for _ in range(2):
        try:
            t = time.perf_counter()
            r = requests.get(PING_URL, proxies=proxies_for(port), timeout=MAX_PING_MS / 1000 + 1,
                             allow_redirects=False)
            ms = (time.perf_counter() - t) * 1000
            if r.status_code == 204 and (best is None or ms < best):
                best = ms
        except Exception:
            pass
    return {"ping": round(best)} if best is not None and best <= MAX_PING_MS else None


def speed_test(node, port):
    got, start = 0, time.perf_counter()
    try:
        with requests.get(SPEED_URL, proxies=proxies_for(port), stream=True, timeout=10) as r:
            r.raise_for_status()
            for chunk in r.iter_content(65536):
                got += len(chunk)
                if time.perf_counter() - start > SPEED_SECONDS:
                    break
    except Exception:
        pass
    el = max(time.perf_counter() - start, 0.001)
    return {"speed": got * 8 / el / 1e6}      # Mbps (0.0 if the download failed)


# ------------------------------------------------------- geo / renaming
def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        try:
            return socket.getaddrinfo(host, None)[0][4][0]
        except Exception:
            return host


def geolocate(ips):
    ips, out = list(set(ips)), {}
    for i in range(0, len(ips), 100):
        try:
            r = requests.post("http://ip-api.com/batch?fields=query,countryCode", json=ips[i:i + 100], timeout=20)
            for item in r.json():
                out[item.get("query")] = item.get("countryCode", "")
        except Exception as e:
            print(f"[!] geo lookup failed: {e}")
        time.sleep(4.5)                       # free tier: 15 batch requests/min
    return out


def flag(cc):
    if cc and len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())
    return "🏳️"


def rename(node, remark):
    if node["proto"] == "vmess":
        d = dict(node["vmess"])
        d["ps"] = remark
        return "vmess://" + base64.b64encode(json.dumps(d, ensure_ascii=False).encode()).decode()
    return node["link"].split("#")[0] + "#" + quote(remark, safe="")


# ------------------------------------------------------------------ main
def main():
    with open(SOURCE_FILE, encoding="utf-8") as f:
        sources = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    nodes, seen = [], set()
    for url in sources:
        for link in fetch_links(url):
            n = parse(link)
            if n and n["key"] not in seen:
                seen.add(n["key"])
                nodes.append(n)
    print(f"[*] {len(nodes)} unique configs")

    print("[*] Alive/ping test")
    alive = run_batches(nodes, PING_BATCH, ping_test, PING_WORKERS)
    if not alive:
        print("[!] nothing alive; keeping previous output")
        return
    alive.sort(key=lambda x: x[1]["ping"])
    alive = alive[:MAX_CONFIGS]
    for rank, (n, r) in enumerate(alive, 1):
        n["ping"], n["rank"] = r["ping"], rank
    print(f"[*] {len(alive)} alive (<= {MAX_PING_MS} ms)")

    print("[*] Speed test")
    tested = [n for n, _ in alive]
    for n, r in run_batches(tested, SPEED_BATCH, speed_test, SPEED_WORKERS):
        n["speed"] = r["speed"]
    final = [n for n in tested if "speed" in n]
    final.sort(key=lambda n: -n["speed"])

    for n in final:
        n["ip"] = resolve(n["host"])
    geo = geolocate([n["ip"] for n in final])

    lines = []
    for n in final:
        remark = f'{n["rank"]} | {flag(geo.get(n["ip"], ""))} | {n["ip"]} | {n["ping"]}ms | {n["speed"]:.1f}Mbps'
        lines.append(rename(n, remark))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] wrote {len(lines)} configs to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
