#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 优选 IP 多端口批量对照测试生成器

用途：
    不修改原来的正式生成器。

    从 gem.yaml 中读取所有有效节点，
    但不再判断原节点是不是 Cloudflare 节点。

    直接取 gem.yaml 中第一个有效节点作为“自建服务器模板”，
    然后把这个模板的 server/IP 替换成优选 Cloudflare IP，
    并测试多个端口。

    一次运行自动测试多个 IP 频次文件：

        ips_1only.txt  → cf_port_test_1only.yaml
        ips_2only.txt  → cf_port_test_2only.yaml
        ips_3only.txt  → cf_port_test_3only.yaml
        ips_4only.txt  → cf_port_test_4only.yaml
        ips_5plus.txt  → cf_port_test_5plus.yaml

    每个 IP 会分别测试：

        80
        443
        8443
        2053
        2083
        2087
        2096

    注意：
        gem.yaml 可以有 5 个、10 个、20 个甚至更多节点。
        本脚本只取第一个有效节点作为测试模板。

        例如：

            自建服务器节点1
            自建服务器节点2
            自建服务器节点3
            ...
            自建服务器节点10

        实际只使用：

            自建服务器节点1

        然后：

            节点1配置
                ↓
            替换 Cloudflare IP
                ↓
            替换测试端口
                ↓
            生成候选节点

    本脚本不会修改原 gem.yaml。
"""

import requests
import yaml
import base64
import json
import copy
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path


# ===================== 测试配置区域 =====================

IP_SOURCES = {
    "1only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_1only.txt",
    "2only": "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_2only.txt",
    "3only": "https://raw.githubusercontent.com/qjlxg/Program/refs/heads/main/ips_3only.txt",
    "4only": "https://raw.githubusercontent.com/qjlxg/Program/refs/heads/main/ips_4only.txt",
    "5plus": "https://raw.githubusercontent.com/qjlxg/Program/refs/heads/main/ips_5plus.txt",
}

TEMPLATE_FILE = Path("gem.yaml")

OUTPUT_PREFIX = "cf_port_test_"

# None = 不限制
# 来源文件里有多少个 IP 就测试多少个
TEST_IP_LIMIT = None

# 测试端口
TEST_PORTS = [
    80,
    443,
    8443,
    2053,
    2083,
    2087,
    2096,
]

# None = 不限制
# 例如 300 = 每个输出文件最多生成 300 个节点
MAX_TOTAL_NODES = 300

# ======================================================


def fetch_ips(url):
    """
    下载 IP 文件。

    支持：

        1.2.3.4
        1.2.3.4:443
        1.2.3.4 # comment

    自动去重。

    TEST_IP_LIMIT = None 时：
        不限制 IP 数量。
    """

    print()
    print("=" * 70)
    print(f"正在读取 IP：{url}")
    print("=" * 70)

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
                line = line.split("#", 1)[0].strip()

            if not line:
                continue

            # 如果是 IP:PORT，则只取 IP
            parts = line.rsplit(":", 1)

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

            # None = 不限制
            if (
                TEST_IP_LIMIT is not None
                and len(ips) >= TEST_IP_LIMIT
            ):
                break

        print(f"成功读取 IP：{len(ips)}")

        for i, ip in enumerate(ips, 1):
            print(f"{i:5d}. {ip}")

        return ips

    except Exception as e:
        print(f"读取 IP 失败：{e}")
        return []


def parse_vmess_uri(uri):
    """
    解析 vmess:// URI。
    """

    try:
        encoded = uri[8:].strip()

        # 兼容缺少 padding
        encoded += "=" * (-len(encoded) % 4)

        decoded = base64.b64decode(
            encoded
        ).decode(
            "utf-8",
            errors="ignore"
        )

        data = json.loads(decoded)

        name = (
            data.get("ps")
            or data.get("remark")
            or "VMess"
        )

        server = (
            data.get("add")
            or data.get("server")
            or ""
        )

        port = int(
            data.get("port")
            or 443
        )

        tls_value = str(
            data.get("tls")
            or ""
        ).lower()

        tls = tls_value in (
            "tls",
            "true",
            "1",
            "xtls",
        )

        if port in (
            443,
            8443,
            2053,
            2083,
            2087,
            2096,
        ):
            tls = True

        proxy = {
            "name": name,
            "type": "vmess",
            "server": server,
            "port": port,
            "uuid": data.get("id", ""),
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

        if tls:
            proxy["tls"] = True

        network = (
            data.get("net")
            or data.get("network")
            or "tcp"
        )

        proxy["network"] = network

        if network == "ws":

            ws_opts = {}

            path = (
                data.get("path")
                or "/"
            )

            host = (
                data.get("host")
                or ""
            )

            ws_opts["path"] = path

            if host:
                ws_opts["headers"] = {
                    "Host": host
                }

            proxy["ws-opts"] = ws_opts

        return proxy

    except Exception:
        return None


def parse_uri_to_proxy(uri):
    """
    解析 vmess:// / vless://。
    """

    uri = uri.strip()

    if uri.startswith("vmess://"):
        return parse_vmess_uri(uri)

    if not uri.startswith("vless://"):
        return None

    try:
        parsed = urlparse(uri)

        uuid = parsed.username

        if not uuid:
            return None

        server = parsed.hostname

        if not server:
            return None

        port = parsed.port or 443

        query = parse_qs(
            parsed.query
        )

        def get_q(name, default=""):
            value = query.get(name)

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

        encryption = get_q(
            "encryption",
            "none"
        )

        network = get_q(
            "type",
            "tcp"
        )

        security = get_q(
            "security",
            ""
        )

        sni = get_q(
            "sni",
            ""
        )

        host = get_q(
            "host",
            ""
        )

        path = get_q(
            "path",
            "/"
        )

        proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "encryption": encryption,
            "network": network,
        }

        if security:
            proxy["tls"] = (
                security == "tls"
            )

        if security == "tls":
            proxy["servername"] = (
                sni or server
            )

        if port in (
            443,
            8443,
            2053,
            2083,
            2087,
            2096,
        ):
            proxy["tls"] = True

            if not proxy.get("servername"):
                proxy["servername"] = (
                    sni
                    or server
                )

        if network == "ws":

            ws_opts = {
                "path": path or "/"
            }

            if host:
                ws_opts["headers"] = {
                    "Host": host
                }

            proxy["ws-opts"] = ws_opts

        return proxy

    except Exception:
        return None


def universal_load_subscription(file_path):
    """
    通用读取：

        YAML
        明文协议链接
        Base64 YAML
        Base64 协议链接
    """

    path = Path(file_path)

    if not path.exists():
        print(
            f"模板文件不存在：{file_path}"
        )
        return {
            "proxies": []
        }

    try:
        raw = path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except Exception as e:
        print(
            f"读取模板失败：{e}"
        )
        return {
            "proxies": []
        }

    raw = raw.strip()

    # ==================================================
    # 1. YAML
    # ==================================================

    try:
        data = yaml.safe_load(raw)

        if isinstance(data, dict):

            proxies = data.get(
                "proxies"
            )

            if isinstance(
                proxies,
                list
            ):
                valid = []

                for node in proxies:
                    if isinstance(
                        node,
                        dict
                    ) and node.get(
                        "server"
                    ):
                        valid.append(
                            node
                        )

                if valid:

                    print(
                        f"【识别成功】当前文件为：YAML 配置，"
                        f"成功提取 {len(valid)} 个有效节点。"
                    )

                    data["proxies"] = valid

                    return data

    except Exception:
        pass

    # ==================================================
    # 2. 明文协议链接
    # ==================================================

    lines = [
        x.strip()
        for x in raw.splitlines()
        if x.strip()
    ]

    proxies = []

    for line in lines:

        if line.startswith(
            (
                "vmess://",
                "vless://",
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

        print(
            f"【识别成功】当前文件为：明文链接列表，"
            f"成功提取 {len(proxies)} 个有效节点。"
        )

        return {
            "proxies": proxies
        }

    # ==================================================
    # 3. Base64
    # ==================================================

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
        )

        decoded = decoded.strip()

        # Base64 → YAML
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

                        if (
                            isinstance(
                                node,
                                dict
                            )
                            and node.get(
                                "server"
                            )
                        ):
                            valid.append(
                                node
                            )

                    if valid:

                        print(
                            f"【识别成功】当前文件为：Base64 YAML，"
                            f"成功提取 {len(valid)} 个有效节点。"
                        )

                        data["proxies"] = valid

                        return data

        except Exception:
            pass

        # Base64 → 明文协议
        proxies = []

        for line in decoded.splitlines():

            line = line.strip()

            if line.startswith(
                (
                    "vmess://",
                    "vless://",
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

            print(
                f"【识别成功】当前文件为：Base64 明文链接，"
                f"成功提取 {len(proxies)} 个有效节点。"
            )

            return {
                "proxies": proxies
            }

    except Exception:
        pass

    print(
        "【识别失败】无法识别模板文件。"
    )

    return {
        "proxies": []
    }


def adapt_node_for_test(
    node,
    server,
    port
):
    """
    把一个原始节点改造成：

        server = 指定 CF IP
        port   = 指定测试端口

    其余配置尽量保持原样。
    """

    proxy = copy.deepcopy(
        node
    )

    original_server = (
        proxy.get("server")
        or ""
    )

    original_name = (
        proxy.get("name")
        or "Template"
    )

    # 保存原始 SNI / Host
    original_servername = (
        proxy.get("servername")
        or proxy.get("sni")
        or ""
    )

    ws_opts = proxy.get(
        "ws-opts"
    )

    original_ws_host = ""

    if isinstance(
        ws_opts,
        dict
    ):

        headers = ws_opts.get(
            "headers"
        )

        if isinstance(
            headers,
            dict
        ):
            original_ws_host = (
                headers.get("Host")
                or headers.get("host")
                or ""
            )

    # ==================================================
    # 替换 server / port
    # ==================================================

    proxy["server"] = server
    proxy["port"] = port

    # ==================================================
    # TLS 端口
    # ==================================================

    tls_ports = (
        443,
        8443,
        2053,
        2083,
        2087,
        2096,
    )

    if port in tls_ports:

        proxy["tls"] = True

        # 优先保留原来的 SNI
        servername = (
            original_servername
            or original_ws_host
            or original_server
        )

        if servername:
            proxy["servername"] = (
                servername
            )

        proxy[
            "skip-cert-verify"
        ] = True

    # ==================================================
    # 80 端口
    # ==================================================

    elif port == 80:

        proxy["tls"] = False

        # 80 明文测试时删除 TLS / Reality
        proxy.pop(
            "client-fingerprint",
            None
        )

        proxy.pop(
            "servername",
            None
        )

        proxy.pop(
            "sni",
            None
        )

        proxy.pop(
            "alpn",
            None
        )

        proxy.pop(
            "reality-opts",
            None
        )

        proxy.pop(
            "fingerprint",
            None
        )

        proxy.pop(
            "flow",
            None
        )

    # ==================================================
    # 保留 WS
    # ==================================================

    # WS 的 path / Host 不改变。
    #
    # 例如：
    #
    # ws-opts:
    #   path: /abc
    #   headers:
    #     Host: xxx.workers.dev
    #
    # 这里仍然保留。

    # 某些配置里可能存在顶层 host，
    # 避免它干扰 server 替换。
    proxy.pop(
        "host",
        None
    )

    # ==================================================
    # 节点名称
    # ==================================================

    proxy["name"] = (
        f"{original_name} | "
        f"IP={server} | "
        f"PORT={port}"
    )

    return proxy


def generate_test_file(
    template_data,
    source_name,
    ip_url
):
    """
    生成一个 IP 来源对应的测试文件。
    """

    print()
    print()
    print("#" * 80)
    print(
        f"开始处理：{source_name}"
    )
    print("#" * 80)

    ips = fetch_ips(
        ip_url
    )

    if not ips:

        print(
            f"{source_name} 没有可用 IP，跳过。"
        )

        return False

    # ==================================================
    # 获取模板节点
    # ==================================================

    all_proxies = template_data.get(
        "proxies",
        []
    )

    if not all_proxies:

        print(
            "gem.yaml 中没有有效节点，退出。"
        )

        return False

    # ==================================================
    # 新逻辑：
    #
    # 不再判断 CF 节点。
    #
    # 直接取第一个有效节点作为母模板。
    # ==================================================

    base_proxy = all_proxies[0]

    print()
    print(
        f"模板总节点：{len(all_proxies)}"
    )

    print(
        "测试模板：第 1 个有效节点"
    )

    print(
        f"模板名称："
        f"{base_proxy.get('name', '未命名')}"
    )

    print(
        f"模板 Server："
        f"{base_proxy.get('server', '')}"
    )

    print(
        f"模板 Port："
        f"{base_proxy.get('port', '')}"
    )

    print(
        f"测试 IP：{len(ips)}"
    )

    print(
        f"测试端口：{len(TEST_PORTS)}"
    )

    theoretical = (
        len(ips)
        * len(TEST_PORTS)
    )

    print(
        f"理论最大组合数量："
        f"{len(ips)} × {len(TEST_PORTS)} "
        f"= {theoretical}"
    )

    # ==================================================
    # 开始生成
    # ==================================================

    new_proxies = []

    stop_all = False

    for ip in ips:

        for port in TEST_PORTS:

            # None = 不限制
            if (
                MAX_TOTAL_NODES is not None
                and len(new_proxies)
                >= MAX_TOTAL_NODES
            ):
                stop_all = True
                break

            new_proxy = adapt_node_for_test(
                base_proxy,
                ip,
                port
            )

            new_proxies.append(
                new_proxy
            )

        if stop_all:
            break

    # ==================================================
    # 输出
    # ==================================================

    output_data = copy.deepcopy(
        template_data
    )

    output_data["proxies"] = (
        new_proxies
    )

    # ==================================================
    # 只建立一个测试代理组
    # ==================================================

    output_data["proxy-groups"] = [
        {
            "name": "CF-Port-Test",
            "type": "select",
            "proxies": [
                proxy["name"]
                for proxy in new_proxies
            ],
        }
    ]

    output_data["rules"] = [
        "MATCH,CF-Port-Test"
    ]

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

        print(
            f"写入失败：{e}"
        )

        return False

    # ==================================================
    # 统计
    # ==================================================

    print()
    print("=" * 70)
    print(
        f"【生成完成】{output_file}"
    )
    print("=" * 70)

    print(
        f"IP 数量：{len(ips)}"
    )

    print(
        f"模板节点：1"
    )

    print(
        f"测试端口：{len(TEST_PORTS)}"
    )

    print(
        f"理论组合："
        f"{len(ips)} × {len(TEST_PORTS)} "
        f"= {theoretical}"
    )

    print(
        f"实际生成："
        f"{len(new_proxies)}"
    )

    if MAX_TOTAL_NODES is not None:
        print(
            f"节点上限："
            f"{MAX_TOTAL_NODES}"
        )
    else:
        print(
            "节点上限：无限制"
        )

    print()
    print(
        "前 10 个测试节点："
    )

    for i, proxy in enumerate(
        new_proxies[:10],
        1
    ):
        print(
            f"{i:3d}. "
            f"{proxy.get('name', '')}"
        )

    return True


def main():

    print()
    print("=" * 80)
    print(
        " Cloudflare 优选 IP 多端口批量对照测试生成器"
    )
    print("=" * 80)

    print()
    print(
        "测试端口："
        + ", ".join(
            str(x)
            for x in TEST_PORTS
        )
    )

    print(
        f"每个来源最多测试 IP："
        f"{TEST_IP_LIMIT}"
    )

    print(
        f"每个输出文件最多生成节点："
        f"{MAX_TOTAL_NODES}"
    )

    print()
    print(
        "【当前模式】"
    )

    print(
        "不识别 CF 节点"
    )

    print(
        "直接使用 gem.yaml 第 1 个有效节点作为模板"
    )

    print()

    # ==================================================
    # 加载模板
    # ==================================================

    template_data = universal_load_subscription(
        TEMPLATE_FILE
    )

    all_proxies = template_data.get(
        "proxies",
        []
    )

    if not all_proxies:

        print(
            "gem.yaml 没有解析出有效节点，退出。"
        )

        return

    print()
    print(
        f"模板总节点："
        f"{len(all_proxies)}"
    )

    print(
        "本次实际使用："
        "第 1 个有效节点作为母模板"
    )

    print(
        f"母模板名称："
        f"{all_proxies[0].get('name', '未命名')}"
    )

    # ==================================================
    # 开始处理 5 个 IP 来源
    # ==================================================

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

    # ==================================================
    # 总结
    # ==================================================

    print()
    print("=" * 80)
    print(
        "全部处理完成"
    )
    print("=" * 80)

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
        "说明："
    )

    print(
        "每个来源文件都会使用同一个母模板，"
        "将其 server 替换为优选 IP，"
        "再按测试端口生成候选节点。"
    )

    print(
        "原 gem.yaml 不会被修改。"
    )


if __name__ == "__main__":
    main()