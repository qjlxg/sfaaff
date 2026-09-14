#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloudflare 优选 IP × 原节点配置批量生成测试版

核心逻辑：

    gem.yaml
        ↓
    读取所有原始节点
        ↓
    每个原始节点自己作为模板
        ↓
    只修改 server = 优选 IP
        ↓
    原节点自己的 port / uuid / password / tls / sni /
    ws / path / host / alpn / fingerprint 等全部保持不变
        ↓
    最多生成 MAX_TOTAL_NODES 个测试节点
        ↓
    输出 cf_port_test_xxx.yaml

重要：

    不再使用“第一个节点作为统一模板”的逻辑。

    例如 gem.yaml 有：

        节点 A
        节点 B
        节点 C

    那么：

        IP1 + 节点A原配置
        IP2 + 节点A原配置

        IP1 + 节点B原配置
        IP2 + 节点B原配置

        IP1 + 节点C原配置
        IP2 + 节点C原配置

    每个节点只替换 server。

    不修改原 gem.yaml。
"""

import base64
import copy
import json

import requests
import yaml

from pathlib import Path
from urllib.parse import (
    urlparse,
    parse_qs,
    unquote,
)


# ============================================================
# 配置
# ============================================================

IP_SOURCES = {
    "1only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_1only.txt",
    "2only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_2only.txt",
    "3only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_3only.txt",
    "4only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_4only.txt",
    "5plus": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_5plus.txt",
}

TEMPLATE_FILE = Path("gem.yaml")

OUTPUT_PREFIX = "cf_port_test_"

# None = 测试来源文件中的全部 IP
TEST_IP_LIMIT = None

# 每个输出文件最多生成多少节点
MAX_TOTAL_NODES = 300


# ============================================================
# 下载 IP
# ============================================================

def fetch_ips(url):
    """
    下载 IP 列表。

    支持：

        1.2.3.4
        1.2.3.4:443
        1.2.3.4 # 注释

    自动去重。
    """

    print()
    print("=" * 80)
    print("读取 IP 来源：")
    print(url)
    print("=" * 80)

    try:

        response = requests.get(
            url,
            timeout=15,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        response.raise_for_status()

        ips = []
        seen = set()

        for raw_line in response.text.splitlines():

            line = raw_line.strip()

            if not line:
                continue

            # 去掉注释
            if "#" in line:

                line = line.split(
                    "#",
                    1
                )[0].strip()

            if not line:
                continue

            # 如果来源中存在 IP:PORT
            # 这里只取 IP
            parts = line.rsplit(
                ":",
                1
            )

            if len(parts) == 2:

                try:

                    int(parts[1])
                    line = parts[0].strip()

                except ValueError:
                    pass

            ip = line.strip()

            if not ip:
                continue

            if ip in seen:
                continue

            seen.add(ip)
            ips.append(ip)

            if (
                TEST_IP_LIMIT is not None
                and len(ips) >= TEST_IP_LIMIT
            ):
                break

        print(
            f"读取到有效 IP：{len(ips)}"
        )

        return ips

    except Exception as e:

        print(
            f"读取 IP 失败：{e}"
        )

        return []


# ============================================================
# VMess
# ============================================================

def parse_vmess_uri(uri):
    """
    VMess URI → Mihomo proxy dict
    """

    try:

        encoded = uri[
            len("vmess://"):
        :].strip()

        encoded += "=" * (
            -len(encoded) % 4
        )

        decoded = base64.b64decode(
            encoded
        ).decode(
            "utf-8",
            errors="ignore"
        )

        data = json.loads(
            decoded
        )

        server = (
            data.get("add")
            or data.get("server")
            or ""
        )

        if not server:
            return None

        port = int(
            data.get("port")
            or 443
        )

        name = (
            data.get("ps")
            or data.get("remark")
            or "VMess"
        )

        proxy = {
            "name": name,
            "type": "vmess",
            "server": server,
            "port": port,
            "uuid": data.get(
                "id",
                ""
            ),
            "alterId": int(
                data.get("aid")
                or data.get("alterId")
                or 0
            ),
            "cipher": data.get(
                "scy",
                "auto"
            ),
        }

        tls = str(
            data.get(
                "tls",
                ""
            )
        ).lower()

        if tls in (
            "tls",
            "true",
            "1",
            "xtls",
        ):
            proxy[
                "tls"
            ] = True

        network = (
            data.get("net")
            or data.get("network")
            or "tcp"
        )

        proxy[
            "network"
        ] = network

        if network == "ws":

            ws_opts = {
                "path": (
                    data.get(
                        "path"
                    )
                    or "/"
                )
            }

            host = (
                data.get("host")
                or ""
            )

            if host:

                ws_opts[
                    "headers"
                ] = {
                    "Host": host
                }

            proxy[
                "ws-opts"
            ] = ws_opts

        # 常见 VMess 字段尽量原样保留
        if data.get("scy"):
            proxy["cipher"] = data["scy"]

        if data.get("sni"):
            proxy["servername"] = data["sni"]

        if data.get("alpn"):

            alpn = data["alpn"]

            if isinstance(
                alpn,
                str
            ):

                proxy[
                    "alpn"
                ] = [
                    x.strip()
                    for x in alpn.split(",")
                    if x.strip()
                ]

        return proxy

    except Exception:
        return None


# ============================================================
# VLESS
# ============================================================

def parse_vless_uri(uri):
    """
    VLESS URI → Mihomo proxy dict
    """

    try:

        parsed = urlparse(
            uri
        )

        uuid = parsed.username

        server = (
            parsed.hostname
            or ""
        )

        if not uuid or not server:
            return None

        port = (
            parsed.port
            or 443
        )

        query = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        def get_q(
            key,
            default=""
        ):

            value = query.get(
                key
            )

            if not value:
                return default

            return unquote(
                value[0]
            )

        name = (
            unquote(
                parsed.fragment
            )
            if parsed.fragment
            else "VLESS"
        )

        proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "encryption": get_q(
                "encryption",
                "none"
            ),
        }

        network = get_q(
            "type",
            "tcp"
        )

        proxy[
            "network"
        ] = network

        security = get_q(
            "security",
            ""
        )

        if security == "tls":

            proxy[
                "tls"
            ] = True

        elif security:

            proxy[
                "tls"
            ] = False

        sni = get_q(
            "sni",
            ""
        )

        if sni:

            proxy[
                "servername"
            ] = sni

        fp = get_q(
            "fp",
            ""
        )

        if fp:

            proxy[
                "client-fingerprint"
            ] = fp

        alpn = query.get(
            "alpn",
            []
        )

        if alpn:

            proxy[
                "alpn"
            ] = [
                unquote(x)
                for x in alpn
            ]

        if network == "ws":

            path = get_q(
                "path",
                "/"
            )

            host = get_q(
                "host",
                ""
            )

            ws_opts = {
                "path": path or "/"
            }

            if host:

                ws_opts[
                    "headers"
                ] = {
                    "Host": host
                }

            proxy[
                "ws-opts"
            ] = ws_opts

        return proxy

    except Exception:
        return None


# ============================================================
# Trojan
# ============================================================

def parse_trojan_uri(uri):
    """
    Trojan URI → Mihomo proxy dict

    例如：

    trojan://password@example.com:443
        ?security=tls
        &sni=example.com
        &alpn=h3
        &fp=randomized
        &allowlnsecure=1
        &type=ws
        &host=example.com
        &path=%2Ftr%3Fed%3D2560
        #节点名称
    """

    try:

        parsed = urlparse(
            uri
        )

        server = (
            parsed.hostname
            or ""
        )

        password = unquote(
            parsed.username
            or ""
        )

        if not server:
            return None

        port = (
            parsed.port
            or 443
        )

        query = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        def get_q(
            key,
            default=""
        ):

            values = query.get(
                key
            )

            if not values:
                return default

            return unquote(
                values[0]
            )

        name = (
            unquote(
                parsed.fragment
            )
            if parsed.fragment
            else "Trojan"
        )

        proxy = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password,
        }

        security = get_q(
            "security",
            ""
        )

        if security == "tls":

            proxy[
                "tls"
            ] = True

        sni = get_q(
            "sni",
            ""
        )

        if sni:

            proxy[
                "sni"
            ] = sni

        # ALPN
        alpn_values = query.get(
            "alpn",
            []
        )

        if alpn_values:

            proxy[
                "alpn"
            ] = [
                unquote(
                    x
                )
                for x in alpn_values
            ]

        # 指纹
        fp = get_q(
            "fp",
            ""
        )

        if fp:

            proxy[
                "client-fingerprint"
            ] = fp

        # allowlnsecure
        allow_insecure = get_q(
            "allowlnsecure",
            ""
        )

        if not allow_insecure:

            allow_insecure = get_q(
                "allowInsecure",
                ""
            )

        if allow_insecure:

            proxy[
                "skip-cert-verify"
            ] = (
                str(
                    allow_insecure
                ).lower()
                in (
                    "1",
                    "true",
                    "yes",
                )
            )

        # 网络类型
        network = get_q(
            "type",
            "tcp"
        )

        proxy[
            "network"
        ] = network

        # WS
        if network == "ws":

            path = get_q(
                "path",
                "/"
            )

            host = get_q(
                "host",
                ""
            )

            ws_opts = {
                "path": path or "/"
            }

            if host:

                ws_opts[
                    "headers"
                ] = {
                    "Host": host
                }

            proxy[
                "ws-opts"
            ] = ws_opts

        return proxy

    except Exception:
        return None


# ============================================================
# URI 统一解析
# ============================================================

def parse_uri_to_proxy(uri):
    """
    支持：

        vmess://
        vless://
        trojan://
    """

    uri = uri.strip()

    if uri.startswith(
        "vmess://"
    ):

        return parse_vmess_uri(
            uri
        )

    if uri.startswith(
        "vless://"
    ):

        return parse_vless_uri(
            uri
        )

    if uri.startswith(
        "trojan://"
    ):

        return parse_trojan_uri(
            uri
        )

    return None


# ============================================================
# 读取 gem.yaml
# ============================================================

def universal_load_subscription(
    file_path
):
    """
    读取 gem.yaml。

    支持：

        1. 标准 YAML
        2. 明文 vmess/vless/trojan
        3. Base64 YAML
        4. Base64 vmess/vless/trojan

    返回：

        {
            "proxies": [...]
        }
    """

    path = Path(
        file_path
    )

    if not path.exists():

        print()
        print(
            f"模板文件不存在："
            f"{file_path}"
        )

        return {
            "proxies": []
        }

    try:

        raw = path.read_text(
            encoding="utf-8",
            errors="ignore"
        ).strip()

    except Exception as e:

        print(
            f"读取模板失败：{e}"
        )

        return {
            "proxies": []
        }

    # ========================================================
    # 1. YAML
    # ========================================================

    try:

        data = yaml.safe_load(
            raw
        )

        if isinstance(
            data,
            dict
        ):

            proxies = data.get(
                "proxies"
            )

            if isinstance(
                proxies,
                list
            ):

                valid = []

                for node in proxies:

                    if not isinstance(
                        node,
                        dict
                    ):
                        continue

                    if not node.get(
                        "server"
                    ):
                        continue

                    if not node.get(
                        "type"
                    ):
                        continue

                    valid.append(
                        node
                    )

                if valid:

                    data[
                        "proxies"
                    ] = valid

                    print()
                    print(
                        "【识别成功】YAML"
                    )

                    print(
                        f"有效节点："
                        f"{len(valid)}"
                    )

                    return data

    except Exception:
        pass

    # ========================================================
    # 2. 明文 URI
    # ========================================================

    proxies = []

    for line in raw.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith(
            (
                "vmess://",
                "vless://",
                "trojan://",
            )
        ):

            proxy = parse_uri_to_proxy(
                line
            )

            if proxy:

                proxies.append(
                    proxy
                )

    if proxies:

        print()
        print(
            "【识别成功】明文节点列表"
        )

        print(
            f"有效节点："
            f"{len(proxies)}"
        )

        return {
            "proxies": proxies
        }

    # ========================================================
    # 3. Base64
    # ========================================================

    try:

        encoded = "".join(
            raw.split()
        )

        encoded += "=" * (
            -len(encoded) % 4
        )

        decoded = base64.b64decode(
            encoded
        ).decode(
            "utf-8",
            errors="ignore"
        ).strip()

        # ----------------------------------------------------
        # Base64 → YAML
        # ----------------------------------------------------

        try:

            data = yaml.safe_load(
                decoded
            )

            if isinstance(
                data,
                dict
            ):

                proxies = data.get(
                    "proxies"
                )

                if isinstance(
                    proxies,
                    list
                ):

                    valid = []

                    for node in proxies:

                        if not isinstance(
                            node,
                            dict
                        ):
                            continue

                        if not node.get(
                            "server"
                        ):
                            continue

                        if not node.get(
                            "type"
                        ):
                            continue

                        valid.append(
                            node
                        )

                    if valid:

                        data[
                            "proxies"
                        ] = valid

                        print()
                        print(
                            "【识别成功】Base64 YAML"
                        )

                        print(
                            f"有效节点："
                            f"{len(valid)}"
                        )

                        return data

        except Exception:
            pass

        # ----------------------------------------------------
        # Base64 → URI
        # ----------------------------------------------------

        proxies = []

        for line in decoded.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith(
                (
                    "vmess://",
                    "vless://",
                    "trojan://",
                )
            ):

                proxy = parse_uri_to_proxy(
                    line
                )

                if proxy:

                    proxies.append(
                        proxy
                    )

        if proxies:

            print()
            print(
                "【识别成功】Base64 节点列表"
            )

            print(
                f"有效节点："
                f"{len(proxies)}"
            )

            return {
                "proxies": proxies
            }

    except Exception:
        pass

    print()
    print(
        "【识别失败】"
    )

    print(
        "gem.yaml 没有解析出有效节点。"
    )

    return {
        "proxies": []
    }


# ============================================================
# 复制一个节点，只修改 server
# ============================================================

def clone_node_with_ip(
    original_node,
    new_ip,
    index
):
    """
    核心函数。

    输入一个原始节点。

    深复制以后：

        只修改：
            server

        name：
            为了避免复制后所有节点同名，
            自动增加 IP 标识。

        其他所有字段：
            完全保留。
    """

    proxy = copy.deepcopy(
        original_node
    )

    original_name = str(
        proxy.get(
            "name",
            f"Node-{index}"
        )
    )

    # ========================================================
    # 唯一真正的连接参数修改
    # ========================================================

    proxy[
        "server"
    ] = new_ip

    # ========================================================
    # 名称只用于区分复制出来的节点
    #
    # 不改变任何连接配置。
    # ========================================================

    proxy[
        "name"
    ] = (
        f"{original_name}"
        f" | {new_ip}"
    )

    return proxy


# ============================================================
# 生成一个来源的 YAML
# ============================================================

def generate_test_file(
    template_data,
    source_name,
    ip_url
):
    """
    一个 IP 来源生成一个 YAML。

    所有原始节点都参与。

    例如：

        原节点 A
        原节点 B
        原节点 C

    每个 IP 都分别复制：

        A + IP
        B + IP
        C + IP

    每个节点只换自己的 server。
    """

    print()
    print()
    print(
        "#" * 80
    )

    print(
        f"开始处理：{source_name}"
    )

    print(
        "#" * 80
    )

    # ========================================================
    # 下载 IP
    # ========================================================

    ips = fetch_ips(
        ip_url
    )

    if not ips:

        print(
            "没有有效 IP，跳过。"
        )

        return False

    # ========================================================
    # 原始节点
    # ========================================================

    original_proxies = (
        template_data.get(
            "proxies",
            []
        )
    )

    if not original_proxies:

        print(
            "没有有效原始节点，跳过。"
        )

        return False

    print()
    print(
        f"原始节点数量："
        f"{len(original_proxies)}"
    )

    print(
        f"IP 数量："
        f"{len(ips)}"
    )

    theoretical = (
        len(original_proxies)
        * len(ips)
    )

    print(
        f"理论生成数量："
        f"{len(original_proxies)} × "
        f"{len(ips)} = "
        f"{theoretical}"
    )

    print(
        f"实际最大生成："
        f"{MAX_TOTAL_NODES}"
    )

    print()
    print(
        "生成规则："
    )

    print(
        "每个原节点使用自己的完整配置，"
        "只替换 server。"
    )

    # ========================================================
    # 生成
    # ========================================================

    new_proxies = []

    stopped = False

    # IP 在外层：
    #
    # IP1:
    #   节点1
    #   节点2
    #   节点3
    #
    # IP2:
    #   节点1
    #   节点2
    #   节点3
    #
    # 这样 300 个上限不会只集中在第一个原节点。

    for ip in ips:

        for index, original_node in enumerate(
            original_proxies,
            1
        ):

            if (
                MAX_TOTAL_NODES is not None
                and len(new_proxies)
                >= MAX_TOTAL_NODES
            ):

                stopped = True
                break

            new_proxy = clone_node_with_ip(
                original_node,
                ip,
                index
            )

            new_proxies.append(
                new_proxy
            )

        if stopped:
            break

    # ========================================================
    # 输出配置
    # ========================================================

    output_data = copy.deepcopy(
        template_data
    )

    output_data[
        "proxies"
    ] = new_proxies

    # ========================================================
    # 代理组
    # ========================================================

    proxy_names = [
        proxy[
            "name"
        ]
        for proxy in new_proxies
    ]

    output_data[
        "proxy-groups"
    ] = [
        {
            "name": "CF-IP-Test",
            "type": "select",
            "proxies": proxy_names,
        }
    ]

    # ========================================================
    # Rules
    # ========================================================

    output_data[
        "rules"
    ] = [
        "MATCH,CF-IP-Test"
    ]

    # ========================================================
    # 输出文件
    # ========================================================

    output_file = (
        f"{OUTPUT_PREFIX}"
        f"{source_name}.yaml"
    )

    try:

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            yaml.dump(
                output_data,
                f,
                allow_unicode=True,
                sort_keys=False,
                width=1000
            )

    except Exception as e:

        print()
        print(
            f"写入文件失败：{e}"
        )

        return False

    # ========================================================
    # 统计
    # ========================================================

    print()
    print(
        "=" * 80
    )

    print(
        "生成完成"
    )

    print(
        "=" * 80
    )

    print(
        f"输出文件："
        f"{output_file}"
    )

    print(
        f"原始节点："
        f"{len(original_proxies)}"
    )

    print(
        f"IP："
        f"{len(ips)}"
    )

    print(
        f"理论组合："
        f"{theoretical}"
    )

    print(
        f"实际生成："
        f"{len(new_proxies)}"
    )

    print()

    # ========================================================
    # 显示原节点分布
    # ========================================================

    print(
        "前 20 个生成节点："
    )

    for i, proxy in enumerate(
        new_proxies[:20],
        1
    ):

        print(
            f"{i:3d}. "
            f"{proxy.get('name', '')}"
        )

    return True


# ============================================================
# 主程序
# ============================================================

def main():

    print()
    print(
        "=" * 80
    )

    print(
        " Cloudflare 优选 IP × 原节点配置测试生成器"
    )

    print(
        "=" * 80
    )

    print()

    print(
        f"模板文件："
        f"{TEMPLATE_FILE}"
    )

    print(
        f"IP 数量限制："
        f"{TEST_IP_LIMIT}"
    )

    print(
        f"每个输出最大节点："
        f"{MAX_TOTAL_NODES}"
    )

    print()

    print(
        "【当前模式】"
    )

    print(
        "每个原节点使用自己的配置"
    )

    print(
        "只修改 server"
    )

    print(
        "不修改原节点的 port / TLS / SNI / WS / Path / "
        "UUID / Password / ALPN / Fingerprint 等配置"
    )

    print()

    # ========================================================
    # 读取 gem.yaml
    # ========================================================

    template_data = universal_load_subscription(
        TEMPLATE_FILE
    )

    original_proxies = (
        template_data.get(
            "proxies",
            []
        )
    )

    if not original_proxies:

        print()
        print(
            "gem.yaml 没有解析出有效节点。"
        )

        return

    # ========================================================
    # 显示原始节点
    # ========================================================

    print()
    print(
        "=" * 80
    )

    print(
        "原始节点列表"
    )

    print(
        "=" * 80
    )

    for index, proxy in enumerate(
        original_proxies,
        1
    ):

        print(
            f"{index:3d}. "
            f"{proxy.get('name', '未命名')}"
            f" | "
            f"type={proxy.get('type', '')}"
            f" | "
            f"server={proxy.get('server', '')}"
            f" | "
            f"port={proxy.get('port', '')}"
        )

    # ========================================================
    # 逐个 IP 来源处理
    # ========================================================

    success_count = 0

    for source_name, ip_url in (
        IP_SOURCES.items()
    ):

        ok = generate_test_file(
            template_data,
            source_name,
            ip_url
        )

        if ok:

            success_count += 1

    # ========================================================
    # 最终统计
    # ========================================================

    print()
    print()
    print(
        "=" * 80
    )

    print(
        "全部处理完成"
    )

    print(
        "=" * 80
    )

    print(
        f"成功生成："
        f"{success_count} / "
        f"{len(IP_SOURCES)}"
    )

    print()

    for source_name in IP_SOURCES:

        output_file = (
            f"{OUTPUT_PREFIX}"
            f"{source_name}.yaml"
        )

        if Path(
            output_file
        ).exists():

            print(
                f"✓ {output_file}"
            )

    print()
    print(
        "原 gem.yaml 未修改。"
    )

    print()
    print(
        "核心规则：每个原节点只替换 server，"
        "其他连接配置保持原节点自己的配置。"
    )


# ============================================================
# Entry
# ============================================================

if __name__ == "__main__":
    main()