#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloudflare 优选 IP 批量替换生成器

功能：
    读取 gem.yaml 中的所有节点。

    对每一个原始节点：
        复制该节点自身的完整配置
        仅将 server 替换成优选 IP

    例如：

        原节点1
            server: www.example.com
            port: 443
            password: xxx
            tls: true
            sni: example.com
            ws-opts: ...
        
        会生成：

            原节点1 + IP1
            原节点1 + IP2
            原节点1 + IP3
            ...

        然后继续：

            原节点2 + IP1
            原节点2 + IP2
            原节点2 + IP3
            ...

    除 server 外，不主动修改任何节点字段。

    不限制最终节点数量。
"""

import base64
import copy
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml


# ============================================================
# 配置
# ============================================================

TEMPLATE_FILE = Path("gem.yaml")

IP_SOURCES = {
    "1only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_1only.txt",
    "2only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_2only.txt",
    "3only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_3only.txt",
    "4only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_4only.txt",
    "5plus": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_5plus.txt",
}

REQUEST_TIMEOUT = 15

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


# ============================================================
# HTTP
# ============================================================

def get_session():
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    })
    return session


# ============================================================
# IP 处理
# ============================================================

IPV4_RE = re.compile(
    r"^(?:"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
    r"){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)


def clean_ip_line(line):
    """
    清理 IP 文件中的一行。

    支持：
        1.2.3.4
        1.2.3.4:443
        1.2.3.4 # comment

    最终只返回 IP。
    """

    line = line.strip()

    if not line:
        return None

    # 去掉注释
    if "#" in line:
        line = line.split("#", 1)[0].strip()

    if not line:
        return None

    # 纯 IPv4
    if IPV4_RE.match(line):
        return line

    # IPv4:PORT
    m = re.match(
        r"^((?:\d{1,3}\.){3}\d{1,3}):\d+$",
        line
    )

    if m:
        ip = m.group(1)

        if IPV4_RE.match(ip):
            return ip

    return None


def fetch_ips(name, url):
    print()
    print("=" * 70)
    print(f"[*] 下载 IP 源：{name}")
    print(f"[*] URL: {url}")

    session = get_session()

    try:
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
    except Exception as e:
        print(f"[!] IP 源下载失败: {e}")
        return []

    ips = []
    seen = set()

    for line in response.text.splitlines():
        ip = clean_ip_line(line)

        if not ip:
            continue

        if ip in seen:
            continue

        seen.add(ip)
        ips.append(ip)

    print(f"[*] 获取有效 IP: {len(ips)}")

    return ips


# ============================================================
# Trojan URI
# ============================================================

def parse_trojan_uri(uri):
    """
    解析 trojan:// URI。
    """

    try:
        parsed = urlparse(uri)

        if parsed.scheme.lower() != "trojan":
            return None

        if not parsed.hostname:
            return None

        node = {
            "name": unquote(parsed.fragment) if parsed.fragment else parsed.hostname,
            "type": "trojan",
            "server": parsed.hostname,
            "port": parsed.port or 443,
            "password": unquote(parsed.username or ""),
        }

        params = parse_qs(parsed.query)

        security = params.get("security", [None])[0]

        if security:
            if security.lower() in ("tls", "reality"):
                node["tls"] = True

        sni = params.get("sni", [None])[0]

        if sni:
            node["sni"] = unquote(sni)

        alpn = params.get("alpn", [None])[0]

        if alpn:
            node["alpn"] = [
                unquote(x.strip())
                for x in alpn.split(",")
                if x.strip()
            ]

        fp = params.get("fp", [None])[0]

        if fp:
            node["client-fingerprint"] = unquote(fp)

        allow_insecure = params.get(
            "allowlnsecure",
            params.get("allowInsecure", [None])
        )[0]

        if allow_insecure is not None:
            node["skip-cert-verify"] = str(
                allow_insecure
            ).lower() in (
                "1",
                "true",
                "yes",
            )

        network = params.get("type", [None])[0]

        if network:
            node["network"] = unquote(network)

        host = params.get("host", [None])[0]

        path = params.get("path", [None])[0]

        if host or path:
            ws_opts = {}

            if path:
                ws_opts["path"] = unquote(path)

            if host:
                ws_opts["headers"] = {
                    "Host": unquote(host)
                }

            node["ws-opts"] = ws_opts

        flow = params.get("flow", [None])[0]

        if flow:
            node["flow"] = unquote(flow)

        return node

    except Exception as e:
        print(f"[!] Trojan URI 解析失败: {e}")
        return None


# ============================================================
# VMess URI
# ============================================================

def parse_vmess_uri(uri):
    """
    解析 vmess:// Base64 URI。
    """

    try:
        raw = uri[8:].strip()

        padding = "=" * (-len(raw) % 4)

        decoded = base64.urlsafe_b64decode(
            raw + padding
        ).decode(
            "utf-8",
            errors="ignore"
        )

        data = yaml.safe_load(decoded)

        if not isinstance(data, dict):
            return None

        node = {
            "name": data.get("ps") or data.get("name") or data.get("add"),
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port", 443)),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
        }

        net = data.get("net")

        if net:
            node["network"] = net

        tls = data.get("tls")

        if tls:
            node["tls"] = True

        sni = data.get("sni")

        if sni:
            node["servername"] = sni

        fp = data.get("fp")

        if fp:
            node["client-fingerprint"] = fp

        host = data.get("host")

        path = data.get("path")

        if host or path:
            ws_opts = {}

            if path:
                ws_opts["path"] = path

            if host:
                ws_opts["headers"] = {
                    "Host": host
                }

            node["ws-opts"] = ws_opts

        return {
            k: v
            for k, v in node.items()
            if v is not None
        }

    except Exception:
        return None


# ============================================================
# VLESS URI
# ============================================================

def parse_vless_uri(uri):
    """
    解析 vless:// URI。
    """

    try:
        parsed = urlparse(uri)

        if parsed.scheme.lower() != "vless":
            return None

        if not parsed.hostname:
            return None

        node = {
            "name": unquote(parsed.fragment)
            if parsed.fragment
            else parsed.hostname,
            "type": "vless",
            "server": parsed.hostname,
            "port": parsed.port or 443,
            "uuid": unquote(parsed.username or ""),
        }

        params = parse_qs(parsed.query)

        security = params.get("security", [None])[0]

        if security == "tls":
            node["tls"] = True

        if security == "reality":
            node["tls"] = True

            reality_opts = {}

            pbk = params.get("pbk", [None])[0]
            sid = params.get("sid", [None])[0]
            spx = params.get("spx", [None])[0]

            if pbk:
                reality_opts["public-key"] = unquote(pbk)

            if sid:
                reality_opts["short-id"] = unquote(sid)

            if spx:
                reality_opts["spider-x"] = unquote(spx)

            if reality_opts:
                node["reality-opts"] = reality_opts

        sni = params.get("sni", [None])[0]

        if sni:
            node["servername"] = unquote(sni)

        fp = params.get("fp", [None])[0]

        if fp:
            node["client-fingerprint"] = unquote(fp)

        flow = params.get("flow", [None])[0]

        if flow:
            node["flow"] = unquote(flow)

        alpn = params.get("alpn", [None])[0]

        if alpn:
            node["alpn"] = [
                unquote(x.strip())
                for x in alpn.split(",")
                if x.strip()
            ]

        network = params.get("type", [None])[0]

        if network:
            node["network"] = unquote(network)

        host = params.get("host", [None])[0]

        path = params.get("path", [None])[0]

        if host or path:
            transport_opts = {}

            if path:
                transport_opts["path"] = unquote(path)

            if host:
                transport_opts["headers"] = {
                    "Host": unquote(host)
                }

            if network == "ws":
                node["ws-opts"] = transport_opts

        return node

    except Exception:
        return None


# ============================================================
# 单条 URI
# ============================================================

def parse_proxy_uri(line):
    line = line.strip()

    if not line:
        return None

    if line.startswith("trojan://"):
        return parse_trojan_uri(line)

    if line.startswith("vmess://"):
        return parse_vmess_uri(line)

    if line.startswith("vless://"):
        return parse_vless_uri(line)

    return None


# ============================================================
# 输入文件解析
# ============================================================

def load_yaml_file(path):
    print()
    print("=" * 70)
    print(f"[*] 读取节点文件: {path}")

    text = path.read_text(
        encoding="utf-8-sig"
    )

    # --------------------------------------------------------
    # 第一优先：标准 YAML
    # --------------------------------------------------------

    try:
        data = yaml.safe_load(text)

        if isinstance(data, dict):
            proxies = data.get("proxies")

            if isinstance(proxies, list):

                valid = []

                for proxy in proxies:
                    if not isinstance(proxy, dict):
                        continue

                    if not proxy.get("server"):
                        continue

                    if not proxy.get("type"):
                        continue

                    valid.append(proxy)

                if valid:
                    print(f"[*] YAML 节点数量: {len(valid)}")
                    return data, valid

        # ----------------------------------------------------
        # YAML 可能只是单纯的 URI 列表
        # ----------------------------------------------------

        if isinstance(data, list):

            valid = []

            for item in data:
                if isinstance(item, str):
                    proxy = parse_proxy_uri(item)

                    if proxy:
                        valid.append(proxy)

            if valid:
                print(f"[*] URI 节点数量: {len(valid)}")

                return {
                    "proxies": valid
                }, valid

    except Exception:
        pass

    # --------------------------------------------------------
    # 第二优先：纯文本 URI
    # --------------------------------------------------------

    proxies = []

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        proxy = parse_proxy_uri(line)

        if proxy:
            proxies.append(proxy)

    if proxies:
        print(f"[*] 纯文本 URI 节点数量: {len(proxies)}")

        return {
            "proxies": proxies
        }, proxies

    # --------------------------------------------------------
    # 第三优先：Base64
    # --------------------------------------------------------

    compact = re.sub(
        r"\s+",
        "",
        text
    )

    try:
        padding = "=" * (-len(compact) % 4)

        decoded = base64.b64decode(
            compact + padding
        ).decode(
            "utf-8",
            errors="ignore"
        )

        proxies = []

        for line in decoded.splitlines():

            line = line.strip()

            if not line:
                continue

            proxy = parse_proxy_uri(line)

            if proxy:
                proxies.append(proxy)

        if proxies:
            print(f"[*] Base64 节点数量: {len(proxies)}")

            return {
                "proxies": proxies
            }, proxies

    except Exception:
        pass

    raise RuntimeError(
        "无法从 gem.yaml 中识别出有效节点"
    )


# ============================================================
# 生成节点
# ============================================================

def generate_nodes(original_proxies, ips):
    """
    核心逻辑：

        原节点1 + 所有 IP
        原节点2 + 所有 IP
        原节点3 + 所有 IP
        ...

    每次 deepcopy 原节点。

    唯一修改：
        proxy["server"] = ip

    不修改：
        name
        type
        port
        password
        uuid
        tls
        sni
        servername
        alpn
        fingerprint
        network
        ws-opts
        reality-opts
        flow
        以及其他所有字段。
    """

    generated = []

    total_original = len(original_proxies)
    total_ips = len(ips)

    print()
    print("=" * 70)
    print("[*] 开始生成")
    print(f"[*] 原始节点: {total_original}")
    print(f"[*] 优选 IP: {total_ips}")
    print(f"[*] 理论生成数量: {total_original * total_ips}")
    print("[*] 数量限制: 无")
    print()

    for node_index, original_node in enumerate(
        original_proxies,
        start=1
    ):

        original_name = original_node.get(
            "name",
            f"Node-{node_index}"
        )

        print(
            f"[*] 节点 {node_index}/{total_original}: "
            f"{original_name}"
        )

        for ip in ips:

            # 完整复制当前节点
            proxy = copy.deepcopy(
                original_node
            )

            # =================================================
            # 唯一允许修改的字段
            # =================================================
            proxy["server"] = ip

            generated.append(proxy)

    return generated


# ============================================================
# 保存 YAML
# ============================================================

def save_yaml(data, output_file):
    print()
    print(f"[*] 写入: {output_file}")

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        yaml.safe_dump(
            data,
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )

    print(
        f"[+] 保存完成: {output_file}"
    )


# ============================================================
# 主程序
# ============================================================

def main():

    print()
    print("=" * 70)
    print(" Cloudflare 优选 IP 批量替换生成器")
    print("=" * 70)
    print()
    print("规则：")
    print("  1. 读取 gem.yaml 全部节点")
    print("  2. 每个节点单独作为模板")
    print("  3. 每个节点套用全部优选 IP")
    print("  4. 只修改 server")
    print("  5. name 不改")
    print("  6. port 不改")
    print("  7. 其他配置全部不改")
    print("  8. 不限制生成数量")
    print()

    # --------------------------------------------------------
    # 读取原始节点
    # --------------------------------------------------------

    if not TEMPLATE_FILE.exists():
        print(
            f"[!] 找不到文件: {TEMPLATE_FILE}"
        )
        return

    try:
        template_data, original_proxies = (
            load_yaml_file(TEMPLATE_FILE)
        )
    except Exception as e:
        print(
            f"[!] 节点文件读取失败: {e}"
        )
        return

    if not original_proxies:
        print("[!] 没有有效节点")
        return

    print()
    print("=" * 70)
    print(f"[*] 最终原始节点数量: {len(original_proxies)}")

    # --------------------------------------------------------
    # 逐个 IP 源生成
    # --------------------------------------------------------

    for source_name, source_url in IP_SOURCES.items():

        ips = fetch_ips(
            source_name,
            source_url
        )

        if not ips:
            print(
                f"[!] {source_name} 没有有效 IP，跳过"
            )
            continue

        generated_nodes = generate_nodes(
            original_proxies,
            ips
        )

        if not generated_nodes:
            print(
                f"[!] {source_name} 没有生成节点"
            )
            continue

        # ----------------------------------------------------
        # 完整复制顶层配置
        # ----------------------------------------------------

        output_data = copy.deepcopy(
            template_data
        )

        # ----------------------------------------------------
        # 仅替换 proxies
        # ----------------------------------------------------

        output_data["proxies"] = generated_nodes

        output_file = (
            f"cf_port_test_{source_name}.yaml"
        )

        save_yaml(
            output_data,
            output_file
        )

        print()
        print(
            f"[+] {source_name} 生成完成"
        )
        print(
            f"[+] 原节点: {len(original_proxies)}"
        )
        print(
            f"[+] IP 数量: {len(ips)}"
        )
        print(
            f"[+] 输出节点: {len(generated_nodes)}"
        )

    print()
    print("=" * 70)
    print(" 全部处理完成")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()