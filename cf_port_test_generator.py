#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 优选 IP 套娃生成器（全量节点 + 防卡死 + 可 GitHub 预筛版）
"""

import requests
import yaml
import base64
import json
import copy
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
from typing import List, Dict, Any
import sys

# ===================== 配置区域 =====================

IP_SOURCES = {
    "1only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_1only.txt",
   # "2only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_2only.txt",
    # 后面的源如果 404 会自动跳过
    "3only": "https://raw.githubusercontent.com/qjlxg/Program/refs/heads/main/ips_3only.txt",
    "4only": "https://raw.githubusercontent.com/qjlxg/Program/refs/heads/main/ips_4only.txt",
    "5plus": "https://raw.githubusercontent.com/qjlxg/Program/refs/heads/main/ips_5plus.txt",
}

TEMPLATE_FILE = Path("gem.yaml")          # 你的节点模板
OUTPUT_PREFIX = "cf_nest_"                # 输出文件前缀
TEST_IP_LIMIT = 5000                       # 每个 IP 源最多取多少个（建议 30~80）
TEST_PORTS = [443,]                        # 强烈建议先只测 443，成功率最高
# TEST_PORTS = [8443,2053,2083,2087,2096]      # 需要多端口时再打开

MAX_NODES_PER_FILE = 5000               # 每个 yaml 最多多少节点，超过自动拆分
PROGRESS_EVERY = 200                      # 每生成多少个打印一次进度

# ======================================================


def fetch_ips(ip_source: str) -> List[str]:
    ips = []
    seen = set()
    try:
        print(f"正在获取 IP：{ip_source}")
        resp = requests.get(ip_source, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            clean = line.split("#", 1)[0].strip()
            if ":" in clean:
                host, port_part = clean.rsplit(":", 1)
                try:
                    int(port_part)
                    clean = host.strip()
                except ValueError:
                    pass
            if clean and clean not in seen:
                seen.add(clean)
                ips.append(clean)
                if TEST_IP_LIMIT and len(ips) >= TEST_IP_LIMIT:
                    break
        print(f"  → 成功加载 {len(ips)} 个 IP")
        return ips
    except Exception as e:
        print(f"  → 获取失败：{e}")
        return []


def is_usable_node(node: dict) -> bool:
    """放宽条件，适配 BPB Trojan / VLESS 等"""
    t = node.get("type", "").lower()
    return t in ("trojan", "vless", "vmess")


def parse_vmess_uri(uri: str) -> dict | None:
    try:
        base64_part = uri[8:].split("#")[0]
        padding = 4 - (len(base64_part) % 4)
        if padding < 4:
            base64_part += "=" * padding
        config = json.loads(base64.b64decode(base64_part).decode("utf-8", errors="ignore"))
        name = config.get("ps", f"vmess-{config.get('add', 'node')}")
        host = config.get("host", "")
        port = int(config.get("port", 443))
        tls_val = str(config.get("tls", "")).lower() == "tls" or port in [443, 8443, 2053, 2083, 2087, 2096]
        proxy = {
            "name": name,
            "server": config.get("add"),
            "port": port,
            "type": "vmess",
            "uuid": config.get("id"),
            "alterId": int(config.get("aid", 0)),
            "cipher": config.get("scy", "auto"),
            "udp": True,
            "tls": tls_val,
            "skip-cert-verify": True,
            "network": config.get("net", "ws"),
        }
        if tls_val:
            proxy["servername"] = host or config.get("add")
        if proxy["network"] == "ws":
            proxy["ws-opts"] = {
                "path": config.get("path", "/?ed=2560"),
                "headers": {"Host": host} if host else {}
            }
        return proxy
    except Exception:
        return None


def parse_trojan_uri(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        password = parsed.username
        server = parsed.hostname
        port = parsed.port or 443
        name = unquote(parsed.fragment) if parsed.fragment else f"trojan-{server}"
        query = parse_qs(parsed.query)
        security = query.get("security", ["tls"])[0]
        net_type = query.get("type", ["ws"])[0]
        sni = query.get("sni", [""])[0]
        host = query.get("host", [""])[0]
        path = unquote(query.get("path", ["/?ed=2560"])[0])
        fp = query.get("fp", ["randomized"])[0]
        alpn = query.get("alpn", ["h3"])[0]

        tls_val = security == "tls" or port in [443, 8443, 2053, 2083, 2087, 2096]
        proxy = {
            "name": name,
            "server": server,
            "port": port,
            "type": "trojan",
            "password": password,
            "network": net_type,
            "udp": True,
            "tls": tls_val,
            "skip-cert-verify": True,
            "client-fingerprint": fp,
        }
        if alpn:
            proxy["alpn"] = alpn if isinstance(alpn, list) else [alpn]
        if tls_val:
            proxy["servername"] = sni or host or server
        if net_type == "ws":
            ws_opts = {"path": path or "/?ed=2560"}
            if host:
                ws_opts["headers"] = {"Host": host}
            proxy["ws-opts"] = ws_opts
        return proxy
    except Exception:
        return None


def parse_uri_to_proxy(uri: str) -> dict | None:
    uri = uri.strip()
    if not uri:
        return None
    if uri.startswith("vmess://"):
        return parse_vmess_uri(uri)
    if uri.startswith("trojan://"):
        return parse_trojan_uri(uri)
    if uri.startswith("vless://"):
        try:
            parsed = urlparse(uri)
            uuid = parsed.username
            server = parsed.hostname
            port = parsed.port or 443
            name = unquote(parsed.fragment) if parsed.fragment else f"vless-{server}"
            query = parse_qs(parsed.query)
            net_type = query.get("type", ["ws"])[0]
            security = query.get("security", ["tls"])[0]
            sni = query.get("sni", [""])[0]
            host = query.get("host", [""])[0]
            path = unquote(query.get("path", ["/?ed=2560"])[0])
            tls_val = security == "tls" or port in [443, 8443, 2053, 2083, 2087, 2096]
            proxy = {
                "name": name,
                "server": server,
                "port": port,
                "type": "vless",
                "uuid": uuid,
                "network": net_type,
                "udp": True,
                "tls": tls_val,
                "skip-cert-verify": True,
            }
            if tls_val:
                proxy["servername"] = sni or host or server
            if net_type == "ws":
                ws_opts = {"path": path or "/?ed=2560"}
                if host:
                    ws_opts["headers"] = {"Host": host}
                proxy["ws-opts"] = ws_opts
            return proxy
        except Exception:
            return None
    return None


def universal_load_subscription(file_path: Path) -> dict:
    if not file_path.exists():
        print(f"错误：找不到模板文件 {file_path}")
        return {}
    content = file_path.read_bytes().decode("utf-8-sig", errors="ignore").strip()

    # 1. YAML
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "proxies" in data:
            print("【识别成功】YAML 明文格式")
            return data
    except Exception:
        pass

    # 2. 明文链接
    proxies = []
    for line in content.splitlines():
        p = parse_uri_to_proxy(line)
        if p:
            proxies.append(p)
    if proxies:
        print(f"【识别成功】明文链接，共 {len(proxies)} 个节点")
        return {"proxies": proxies, "proxy-groups": [], "rules": []}

    # 3. Base64
    clean = "".join(content.split())
    for pad in ["", "=", "==", "==="]:
        try:
            decoded = base64.b64decode(clean + pad).decode("utf-8", errors="ignore")
            if decoded.strip():
                break
        except Exception:
            continue
    else:
        decoded = ""

    if decoded:
        try:
            data = yaml.safe_load(decoded)
            if isinstance(data, dict) and "proxies" in data:
                print("【识别成功】Base64 YAML")
                return data
        except Exception:
            pass
        proxies = []
        for line in decoded.splitlines():
            p = parse_uri_to_proxy(line)
            if p:
                proxies.append(p)
        if proxies:
            print(f"【识别成功】Base64 链接，共 {len(proxies)} 个节点")
            return {"proxies": proxies, "proxy-groups": [], "rules": []}

    print("【解析失败】无法识别模板格式")
    return {}


def adapt_node(node: dict, server: str, port: int) -> dict:
    new_node = copy.deepcopy(node)
    new_node["server"] = server
    new_node["port"] = port

    is_tls_port = port in [443, 8443, 2053, 2083, 2087, 2096]
    if is_tls_port:
        new_node["tls"] = True
        new_node["skip-cert-verify"] = True
        domain = (node.get("servername") or node.get("sni") or
                  node.get("ws-opts", {}).get("headers", {}).get("Host"))
        if domain:
            new_node["servername"] = domain
    else:
        new_node["tls"] = False
        new_node["skip-cert-verify"] = True
        for k in ["client-fingerprint", "servername", "sni", "alpn", "reality-opts", "fingerprint", "flow"]:
            new_node.pop(k, None)

    if "ws-opts" in new_node:
        ws = new_node["ws-opts"]
        path = ws.get("path") or "/?ed=2560"
        host = None
        if isinstance(ws.get("headers"), dict):
            host = ws["headers"].get("Host")
        if not host:
            host = node.get("servername") or node.get("sni")
        clean_ws = {"path": path}
        if host:
            clean_ws["headers"] = {"Host": host}
        new_node["ws-opts"] = clean_ws

    new_node.pop("host", None)
    base_name = node.get("name", "node")
    new_node["name"] = f"{base_name} | IP={server} | PORT={port}"
    return new_node


def save_yaml(proxies: List[dict], filepath: str):
    data = {
        "proxies": proxies,
        "proxy-groups": [{
            "name": "CF-Nest-Test",
            "type": "select",
            "proxies": [p["name"] for p in proxies]
        }],
        "rules": ["MATCH,CF-Nest-Test"]
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False, width=1000)
    print(f"  → 已保存：{filepath}（{len(proxies)} 个节点）")


def generate_for_source(template_proxies: List[dict], source_name: str, ip_source: str):
    print("\n" + "=" * 60)
    print(f"处理 IP 源：{source_name}")
    print("=" * 60)

    ips = fetch_ips(ip_source)
    if not ips:
        print("无可用 IP，跳过")
        return

    usable = [p for p in template_proxies if is_usable_node(p)]
    print(f"可用基础节点：{len(usable)} 个")
    print(f"测试端口：{TEST_PORTS}")
    print(f"预计生成：约 {len(usable) * len(ips) * len(TEST_PORTS)} 个节点")

    file_idx = 1
    current_batch = []
    total_generated = 0

    for i, base in enumerate(usable, 1):
        for ip in ips:
            for port in TEST_PORTS:
                node = adapt_node(base, ip, port)
                current_batch.append(node)
                total_generated += 1

                if total_generated % PROGRESS_EVERY == 0:
                    print(f"  已生成 {total_generated} 个节点...")

                if len(current_batch) >= MAX_NODES_PER_FILE:
                    out_name = f"{OUTPUT_PREFIX}{source_name}_{file_idx:02d}.yaml"
                    save_yaml(current_batch, out_name)
                    current_batch = []
                    file_idx += 1

    if current_batch:
        out_name = f"{OUTPUT_PREFIX}{source_name}_{file_idx:02d}.yaml"
        save_yaml(current_batch, out_name)

    print(f"\n源 {source_name} 完成，共生成 {total_generated} 个节点")


def main():
    print("=" * 60)
    print(" Cloudflare 优选 IP 全量套娃生成器（防卡死版）")
    print("=" * 60)
    print(f"模板文件：{TEMPLATE_FILE}")
    print(f"每文件最大节点：{MAX_NODES_PER_FILE}")
    print(f"测试端口：{TEST_PORTS}")
    print(f"每源 IP 上限：{TEST_IP_LIMIT}")

    template = universal_load_subscription(TEMPLATE_FILE)
    if not template:
        return

    all_proxies = template.get("proxies", [])
    if not all_proxies:
        print("模板中没有节点")
        return

    print(f"\n模板总节点：{len(all_proxies)}")

    for name, url in IP_SOURCES.items():
        generate_for_source(all_proxies, name, url)

    print("\n" + "=" * 60)
    print("全部完成！生成的文件可直接用于本地或上传 GitHub 预筛")
    print("=" * 60)


if __name__ == "__main__":
    main()
