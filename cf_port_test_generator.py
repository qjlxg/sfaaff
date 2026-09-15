#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloudflare 优选 IP × Trojan 来源节点批量生成器

来源：
    gem.txt

来源格式：
    trojan://password@server:443?security=tls&sni=xxx&alpn=h3&...

核心逻辑：
    每一个来源节点都是独立模板。
    对每一个来源节点，依次替换全部 IP。

例如：

    来源节点1 + IP1
    来源节点1 + IP2
    来源节点1 + IP3
    ...
    来源节点2 + IP1
    来源节点2 + IP2
    来源节点2 + IP3
    ...

只修改：
    server

完全保留：
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
    path
    host
    flow
    reality-opts
    以及来源 URI 中的其它参数。

不限制生成节点数量。
"""

import base64
import copy
import ipaddress
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote

import requests
import yaml


# ============================================================
# 配置
# ============================================================

SOURCE_FILE = Path("gem.yaml")

IP_SOURCES = {
    "1only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_1only.txt",
    "2only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_2only.txt",
    "3only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_3only.txt",
    "4only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_4only.txt",
    "5plus": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_5plus.txt",
}

OUTPUT_PREFIX = "cf_port_test"

REQUEST_TIMEOUT = 20

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0 Safari/537.36"
)


# ============================================================
# YAML 加速
# ============================================================

try:
    from yaml import CDumper as Dumper
except ImportError:
    from yaml import SafeDumper as Dumper


# ============================================================
# 下载 IP
# ============================================================

def fetch_ips(url):
    print(f"[*] 下载 IP：{url}")

    headers = {
        "User-Agent": USER_AGENT
    }

    r = requests.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT
    )
    r.raise_for_status()

    ips = []
    seen = set()

    for raw in r.text.splitlines():
        line = raw.strip()

        if not line:
            continue

        # 去注释
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        if not line:
            continue

        # 有些文件可能带端口
        if ":" in line and "." in line:
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)(?::\d+)?$", line)
            if m:
                line = m.group(1)

        try:
            ipaddress.ip_address(line)
        except ValueError:
            continue

        if line not in seen:
            seen.add(line)
            ips.append(line)

    print(f"[*] 有效 IP：{len(ips)}")

    return ips


# ============================================================
# 读取来源节点
# ============================================================

def load_source_nodes():
    if not SOURCE_FILE.exists():
        print(f"[!] 找不到来源文件：{SOURCE_FILE}")
        sys.exit(1)

    text = SOURCE_FILE.read_text(
        encoding="utf-8-sig"
    )

    nodes = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        # 只处理 Trojan
        if not line.lower().startswith("trojan://"):
            continue

        nodes.append(line)

    print(f"[*] 来源 Trojan 节点：{len(nodes)}")

    return nodes


# ============================================================
# Trojan URI → Mihomo 节点
# ============================================================

def trojan_to_proxy(uri):
    """
    把单个 Trojan URI 转成 Mihomo proxy。

    注意：
        这里不会套用其它节点的参数。
        每个 URI 单独解析。
    """

    parsed = urlsplit(uri)

    if parsed.scheme.lower() != "trojan":
        return None

    # --------------------------------------------------------
    # password
    # --------------------------------------------------------

    password = unquote(parsed.username or "")

    # --------------------------------------------------------
    # server
    # --------------------------------------------------------

    server = parsed.hostname

    if not server:
        return None

    # --------------------------------------------------------
    # port
    # --------------------------------------------------------

    port = parsed.port or 443

    # --------------------------------------------------------
    # name
    # --------------------------------------------------------

    name = unquote(parsed.fragment) if parsed.fragment else ""

    # --------------------------------------------------------
    # query
    # --------------------------------------------------------

    query = parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    def q(name, default=None):
        values = query.get(name)

        if not values:
            return default

        return unquote(values[0])

    proxy = {
        "name": name or server,
        "type": "trojan",
        "server": server,
        "port": port,
        "password": password,
    }

    # ========================================================
    # TLS
    # ========================================================

    security = q("security")

    if security == "tls":
        proxy["tls"] = True

    # ========================================================
    # SNI
    # ========================================================

    sni = q("sni")

    if sni:
        proxy["sni"] = sni

    # ========================================================
    # ALPN
    # ========================================================

    alpn = q("alpn")

    if alpn:
        # 例如：
        # alpn=h3
        #
        # → ["h3"]

        proxy["alpn"] = [
            x.strip()
            for x in alpn.split(",")
            if x.strip()
        ]

    # ========================================================
    # fingerprint
    # ========================================================

    fp = q("fp")

    if fp:
        proxy["fingerprint"] = fp

    # ========================================================
    # allowInsecure
    # ========================================================

    allow_insecure = q("allowlnsecure")

    if allow_insecure is None:
        # 兼容正确拼写
        allow_insecure = q("allowInsecure")

    if allow_insecure is not None:
        proxy["skip-cert-verify"] = (
            allow_insecure.lower()
            in (
                "1",
                "true",
                "yes",
                "on",
            )
        )

    # ========================================================
    # network
    # ========================================================

    network = q("type")

    if network:
        proxy["network"] = network

    # ========================================================
    # WebSocket
    # ========================================================

    ws_host = q("host")
    ws_path = q("path")

    if network == "ws":

        ws_opts = {}

        if ws_path:
            ws_opts["path"] = ws_path

        if ws_host:
            ws_opts["headers"] = {
                "Host": ws_host
            }

        if ws_opts:
            proxy["ws-opts"] = ws_opts

    # ========================================================
    # flow
    # ========================================================

    flow = q("flow")

    if flow:
        proxy["flow"] = flow

    # ========================================================
    # Reality / Public Key
    # ========================================================

    pbk = q("pbk")
    sid = q("sid")

    if pbk or sid:

        reality_opts = {}

        if pbk:
            reality_opts["public-key"] = pbk

        if sid:
            reality_opts["short-id"] = sid

        proxy["reality-opts"] = reality_opts

    return proxy


# ============================================================
# 解析全部来源节点
# ============================================================

def parse_source_nodes(source_lines):

    proxies = []

    total = len(source_lines)

    print(f"[*] 开始解析 {total} 个来源节点...")

    for i, uri in enumerate(source_lines, 1):

        proxy = trojan_to_proxy(uri)

        if proxy is not None:
            proxies.append(proxy)

        # 每 500 个显示一次
        if i % 500 == 0 or i == total:
            print(
                f"    解析进度：{i}/{total}"
            )

    print(f"[*] 成功解析：{len(proxies)}")

    return proxies


# ============================================================
# 生成
# ============================================================

def generate_yaml(source_proxies, ips, output_file):

    node_count = len(source_proxies)
    ip_count = len(ips)

    total = node_count * ip_count

    print()
    print("=" * 70)
    print(f"来源节点：{node_count}")
    print(f"优选 IP ：{ip_count}")
    print(f"预计生成：{total}")
    print(f"输出文件：{output_file}")
    print("=" * 70)

    start_time = time.time()

    generated = []

    # ========================================================
    # 核心：
    #
    # 每一个来源节点自己复制
    # 只修改 server
    #
    # 节点1 → IP1/IP2/IP3...
    # 节点2 → IP1/IP2/IP3...
    #
    # 绝对不会拿节点1套给节点2
    # ========================================================

    for node_index, original_node in enumerate(
        source_proxies,
        1
    ):

        for ip in ips:

            # 浅复制已经足够。
            #
            # 我们只修改顶层 server，
            # 不修改任何嵌套结构。
            #
            # 比 deepcopy 快很多。
            proxy = original_node.copy()

            proxy["server"] = ip

            generated.append(proxy)

        # 不逐节点打印
        # 每 10% 显示一次
        if (
            node_index == 1
            or node_index == node_count
            or node_index % max(1, node_count // 10) == 0
        ):

            percent = (
                node_index / node_count * 100
            )

            elapsed = time.time() - start_time

            print(
                f"    生成：{percent:6.1f}% "
                f"({node_index}/{node_count}) "
                f"已生成 {len(generated)} "
                f"耗时 {elapsed:.1f}s"
            )

    print()
    print("[*] 开始写入 YAML...")

    # ========================================================
    # Mihomo 标准结构
    # ========================================================

    output_data = {
        "proxies": generated
    }

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        yaml.dump(
            output_data,
            f,
            Dumper=Dumper,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False
        )

    elapsed = time.time() - start_time

    print()
    print(
        f"[+] 完成：{output_file}"
    )

    print(
        f"[+] 节点数量：{len(generated)}"
    )

    print(
        f"[+] 总耗时：{elapsed:.1f} 秒"
    )

    # 释放内存
    del generated


# ============================================================
# 主程序
# ============================================================

def main():

    print()
    print("=" * 70)
    print(" Cloudflare 优选 IP × Trojan 来源节点批量生成器")
    print("=" * 70)
    print()

    # --------------------------------------------------------
    # 1. 读取来源
    # --------------------------------------------------------

    source_lines = load_source_nodes()

    if not source_lines:
        print("[!] 没有找到 Trojan 来源节点")
        return

    # --------------------------------------------------------
    # 2. 解析来源
    # --------------------------------------------------------

    source_proxies = parse_source_nodes(
        source_lines
    )

    if not source_proxies:
        print("[!] 没有成功解析任何节点")
        return

    # --------------------------------------------------------
    # 3. 依次处理 5 个 IP 文件
    # --------------------------------------------------------

    for key, url in IP_SOURCES.items():

        print()
        print("#" * 70)
        print(f"开始处理：{key}")
        print("#" * 70)

        try:
            ips = fetch_ips(url)

        except Exception as e:

            print(
                f"[!] 下载失败：{key}"
            )

            print(
                f"    {e}"
            )

            continue

        if not ips:
            print(
                f"[!] {key} 没有有效 IP，跳过"
            )
            continue

        output_file = (
            f"{OUTPUT_PREFIX}_{key}.yaml"
        )

        try:

            generate_yaml(
                source_proxies,
                ips,
                output_file
            )

        except Exception as e:

            print()
            print(
                f"[!] 生成失败：{output_file}"
            )

            print(
                f"    {type(e).__name__}: {e}"
            )

    print()
    print("=" * 70)
    print("全部处理完成")
    print("=" * 70)


if __name__ == "__main__":
    main()