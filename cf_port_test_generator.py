#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 优选 IP 多端口批量对照测试生成器

用途：
    不修改原来的正式生成器。

    一次运行自动测试多个 IP 频次文件：

        ips_1only.txt  → cf_port_test_ir1only.yaml
        ips_2only.txt  → cf_port_test_ir2only.yaml
        ips_3only.txt  → cf_port_test_ir3only.yaml
        ips_4only.txt  → cf_port_test_ir4only.yaml
        ips_5plus.txt  → cf_port_test_ir5plus.yaml

    核心逻辑：

        原始节点：

            server = www.vpslook.com
            SNI    = yorsunx.xyz
            Host   = yorsunx.xyz
            Path   = /tr?ed=2560

        测试时：

            server = Cloudflare IP
            SNI    = yorsunx.xyz
            Host   = yorsunx.xyz
            Path   = /tr?ed=2560

        即：

            只把连接地址域名直接替换成 IP。

        不修改：
            UUID
            password
            SNI
            Host
            WS Path
            TLS
            fingerprint
            ALPN
            其它原始参数

    每个 IP 分别测试：

         80
         443
         8443
         2053
         2083
         2087
         2096

    同一个：
        IP
        节点参数
        SNI
        WS Host
        WS Path

    对照测试不同端口。

本脚本不会修改原 gem.yaml。
"""

import requests
import yaml
import base64
import json
import copy

from urllib.parse import (
    urlparse,
    parse_qs,
    unquote
)

from pathlib import Path


# ===================== 测试配置区域 =====================

# 优选 IP 来源
#
# 一次运行自动处理下面 5 个文件。
#
IP_SOURCES = {

    "1only":
        "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_1only.txt",

    "2only":
        "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_2only.txt",

    "3only":
        "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_3only.txt",

    "4only":
        "https://raw.githubusercontent.com/qjlxg/Psfaaff/refs/heads/main/ips_4only.txt",

    "5plus":
        "https://raw.githubusercontent.com/qjlxg/sfaaff/refs/heads/main/ips_5plus.txt",
}


# 原模板
TEMPLATE_FILE = Path("gem.yaml")


# 输出文件名前缀
#
# 最终自动生成：
#
# cf_port_test_ir1only.yaml
# cf_port_test_ir2only.yaml
# cf_port_test_ir3only.yaml
# cf_port_test_ir4only.yaml
# cf_port_test_ir5plus.yaml
#
OUTPUT_PREFIX = "cf_port_test_ir"


# 最多测试多少个 IP
#
# None = 不限制
#
TEST_IP_LIMIT = None


# 要测试的端口
TEST_PORTS = [
    80,
    443,
    8443,
    2053,
    2083,
    2087,
    2096,
]


# 每个输出文件最多生成多少节点
#
# None = 不限制
#
MAX_TOTAL_NODES = None


# ======================================================


def fetch_ips(
    ip_source: str
) -> list:

    """
    从指定 IP 来源获取 IP。

    支持：

        1.1.1.1
        1.1.1.1:443
        1.1.1.1#备注

    测试版不使用源文件里的端口。

    所有 IP 都会分别套用 TEST_PORTS。
    """

    ips = []

    seen = set()

    try:

        print(
            f"正在获取测试 IP：{ip_source}"
        )

        resp = requests.get(
            ip_source,
            timeout=15,
            headers={
                "User-Agent":
                    "Mozilla/5.0"
            }
        )

        resp.raise_for_status()

        for line in resp.text.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            # ------------------------------------------
            # 去掉备注
            # ------------------------------------------

            clean_line = line.split(
                "#",
                1
            )[0].strip()

            # ------------------------------------------
            # 如果源里面本身带端口
            #
            # 例如：
            #
            # 1.1.1.1:443
            #
            # 这里只保留 IP。
            # ------------------------------------------

            if ":" in clean_line:

                parts = clean_line.rsplit(
                    ":",
                    1
                )

                if len(parts) == 2:

                    host = parts[0].strip()

                    try:

                        int(parts[1])

                        clean_line = host

                    except ValueError:

                        pass

            if not clean_line:
                continue

            # ------------------------------------------
            # 去重
            # ------------------------------------------

            if clean_line in seen:
                continue

            seen.add(
                clean_line
            )

            ips.append(
                clean_line
            )

            if (
                TEST_IP_LIMIT is not None
                and len(ips) >= TEST_IP_LIMIT
            ):

                break

        print(
            f"成功加载测试 IP："
            f"{len(ips)} 个"
        )

        if ips:

            print(
                "\n测试 IP："
            )

            for ip in ips:

                print(
                    f"  {ip}"
                )

        return ips

    except Exception as e:

        print(
            f"获取 IP 失败：{e}"
        )

        return []


def is_cf_node(
    node: dict
) -> bool:

    server = str(
        node.get(
            "server",
            ""
        )
    ).lower()

    sni = str(
        node.get("sni")
        or node.get("servername")
        or ""
    ).lower()

    ws_headers = str(
        node.get(
            "ws-opts",
            {}
        ).get(
            "headers",
            {}
        )
    ).lower()

    cf_keywords = [
        ".workers.dev",
        ".pages.dev",
        ".boats",
        "lingering-brook",
        "自建",
        "qjixg",
    ]

    return (
        any(
            k in server
            for k in cf_keywords
        )
        or
        any(
            k in sni
            for k in cf_keywords
        )
        or
        any(
            k in ws_headers
            for k in cf_keywords
        )
    )


def parse_vmess_uri(
    uri: str
) -> dict:

    try:

        base64_part = (
            uri[8:]
            .split("#")[0]
        )

        padding = (
            4 -
            (
                len(base64_part) % 4
            )
        )

        if padding < 4:

            base64_part += (
                "=" * padding
            )

        decoded_bytes = (
            base64.b64decode(
                base64_part
            )
        )

        config = json.loads(
            decoded_bytes.decode(
                "utf-8",
                errors="ignore"
            )
        )

        name = config.get(
            "ps",
            f"vmess-{config.get('add', 'node')}"
        )

        host = config.get(
            "host",
            ""
        )

        port = int(
            config.get(
                "port",
                443
            )
        )

        tls_val = (
            True
            if
            str(
                config.get(
                    "tls",
                    ""
                )
            ).lower() == "tls"
            or
            port in [
                443,
                8443,
                2053,
                2083,
                2087,
                2096,
            ]
            else False
        )

        proxy = {

            "name":
                name,

            "server":
                config.get("add"),

            "port":
                port,

            "type":
                "vmess",

            "uuid":
                config.get("id"),

            "alterId":
                int(
                    config.get(
                        "aid",
                        0
                    )
                ),

            "cipher":
                config.get(
                    "scy",
                    "auto"
                ),

            "udp":
                True,

            "tls":
                tls_val,

            "skip-cert-verify":
                True,

            "network":
                config.get(
                    "net",
                    "ws"
                ),
        }

        if tls_val:

            proxy["servername"] = (
                host
                or
                config.get("add")
            )

        if proxy["network"] == "ws":

            proxy["ws-opts"] = {

                "path":
                    config.get(
                        "path",
                        "/?ed=2560"
                    ),

                "headers":
                    {
                        "Host": host
                    }
                    if host
                    else {}
            }

        return proxy

    except Exception:

        return None


def parse_trojan_uri(
    uri: str
) -> dict:

    """
    解析 Trojan URI。

    例如：

    trojan://password@www.vpslook.com:443
        ?security=tls
        &sni=yorsunx.xyz
        &alpn=h3
        &fp=randomized
        &allowlnsecure=1
        &type=ws
        &host=yorsunx.xyz
        &path=%2Ftr%3Fed%3D2560
        #BPB-yorsunx.xyz

    这里特别保留：

        server
        password
        SNI
        Host
        Path
        ALPN
        fingerprint
        allowInsecure
        network

    后面测试时只替换 server 和 port。
    """

    try:

        parsed = urlparse(
            uri
        )

        # ------------------------------------------
        # 用户名位置就是 Trojan password
        # ------------------------------------------

        password = parsed.username

        if password is None:
            return None

        password = unquote(
            password
        )

        # ------------------------------------------
        # 原始服务器地址
        # ------------------------------------------

        server = parsed.hostname

        if not server:
            return None

        # ------------------------------------------
        # 原始端口
        # ------------------------------------------

        port = (
            parsed.port
            or 443
        )

        # ------------------------------------------
        # 节点名称
        # ------------------------------------------

        name = (
            unquote(
                parsed.fragment
            )
            if parsed.fragment
            else
            f"trojan-{server}"
        )

        # ------------------------------------------
        # Query
        # ------------------------------------------

        query = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        security = query.get(
            "security",
            ["tls"]
        )[0]

        sni = query.get(
            "sni",
            [""]
        )[0]

        host = query.get(
            "host",
            [""]
        )[0]

        alpn = query.get(
            "alpn",
            []
        )[0]

        fp = query.get(
            "fp",
            [""]
        )[0]

        network = query.get(
            "type",
            ["tcp"]
        )[0]

        path = unquote(
            query.get(
                "path",
                ["/?ed=2560"]
            )[0]
        )

        allow_insecure = query.get(
            "allowlnsecure",
            query.get(
                "allowInsecure",
                ["1"]
            )
        )[0]

        # ------------------------------------------
        # TLS
        # ------------------------------------------

        tls_val = (
            True
            if
            security == "tls"
            or
            port in [
                443,
                8443,
                2053,
                2083,
                2087,
                2096,
            ]
            else False
        )

        proxy = {

            "name":
                name,

            "server":
                server,

            "port":
                port,

            "type":
                "trojan",

            "password":
                password,

            "udp":
                True,

            "tls":
                tls_val,

            "skip-cert-verify":
                str(
                    allow_insecure
                ).lower()
                in [
                    "1",
                    "true",
                    "yes",
                ],

            "network":
                network,
        }

        # ------------------------------------------
        # SNI
        # ------------------------------------------

        if tls_val:

            proxy["servername"] = (
                sni
                or
                host
                or
                server
            )

        # ------------------------------------------
        # ALPN
        #
        # 保留原始值。
        # ------------------------------------------

        if alpn:

            proxy["alpn"] = [
                alpn
            ]

        # ------------------------------------------
        # fingerprint
        # ------------------------------------------

        if fp:

            proxy["client-fingerprint"] = fp

        # ------------------------------------------
        # WS
        # ------------------------------------------

        if network == "ws":

            ws_opts = {

                "path":
                    path
                    if path
                    else "/?ed=2560"
            }

            if host:

                ws_opts["headers"] = {

                    "Host":
                        host
                }

            proxy["ws-opts"] = (
                ws_opts
            )

        return proxy

    except Exception:

        return None


def parse_uri_to_proxy(
    uri: str
) -> dict:

    uri = uri.strip()

    if not uri:
        return None

    # ------------------------------------------
    # VMess
    # ------------------------------------------

    if uri.startswith(
        "vmess://"
    ):

        return parse_vmess_uri(
            uri
        )

    # ------------------------------------------
    # Trojan
    # ------------------------------------------

    if uri.startswith(
        "trojan://"
    ):

        return parse_trojan_uri(
            uri
        )

    try:

        # ------------------------------------------
        # VLESS
        # ------------------------------------------

        if uri.startswith(
            "vless://"
        ):

            parsed = urlparse(
                uri
            )

            uuid = parsed.username

            server = parsed.hostname

            port = (
                parsed.port
                or 443
            )

            name = (
                unquote(
                    parsed.fragment
                )
                if parsed.fragment
                else
                f"vless-{server}"
            )

            query = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            encryption = query.get(
                "encryption",
                ["none"]
            )[0]

            net_type = query.get(
                "type",
                ["ws"]
            )[0]

            security = query.get(
                "security",
                ["tls"]
            )[0]

            sni = query.get(
                "sni",
                [""]
            )[0]

            host = query.get(
                "host",
                [""]
            )[0]

            path = unquote(
                query.get(
                    "path",
                    ["/?ed=2560"]
                )[0]
            )

            tls_val = (
                True
                if
                security == "tls"
                or
                port in [
                    443,
                    8443,
                    2053,
                    2083,
                    2087,
                    2096,
                ]
                else False
            )

            proxy = {

                "name":
                    name,

                "server":
                    server,

                "port":
                    port,

                "type":
                    "vless",

                "uuid":
                    uuid,

                "cipher":
                    encryption,

                "network":
                    net_type,

                "udp":
                    True,

                "tls":
                    tls_val,

                "skip-cert-verify":
                    True,
            }

            if tls_val:

                proxy["servername"] = (
                    sni
                    or
                    host
                    or
                    server
                )

            if net_type == "ws":

                ws_opts = {

                    "path":
                        path
                        if path
                        else
                        "/?ed=2560"
                }

                if host:

                    ws_opts[
                        "headers"
                    ] = {

                        "Host":
                            host
                    }

                proxy[
                    "ws-opts"
                ] = ws_opts

            return proxy

    except Exception:

        pass

    return None


def universal_load_subscription(
    file_path: Path
) -> dict:

    if not file_path.exists():

        print(
            f"错误：找不到文件 "
            f"[{file_path}]"
        )

        return {}

    raw_content = (
        file_path.read_bytes()
    )

    content = raw_content.decode(
        "utf-8-sig",
        errors="ignore"
    ).strip()

    # --------------------------------------------------
    # 1. YAML
    # --------------------------------------------------

    try:

        data = yaml.safe_load(
            content
        )

        if (
            isinstance(data, dict)
            and
            "proxies" in data
        ):

            print(
                "【识别成功】当前模板为："
                "YAML 明文格式。"
            )

            return data

    except Exception:

        pass

    # --------------------------------------------------
    # 2. 明文链接
    # --------------------------------------------------

    proxies = []

    for line in content.splitlines():

        proxy = parse_uri_to_proxy(
            line
        )

        if proxy:

            proxies.append(
                proxy
            )

    if proxies:

        print(
            f"【识别成功】当前文件为："
            f"明文链接列表，成功提取 "
            f"{len(proxies)} 个有效节点。"
        )

        return {

            "proxies":
                proxies,

            "proxy-groups":
                [],

            "rules":
                []
        }

    # --------------------------------------------------
    # 3. Base64
    # --------------------------------------------------

    clean_base64 = "".join(
        content.split()
    )

    decoded_str = ""

    for padding in [
        "",
        "=",
        "==",
        "===",
    ]:

        try:

            padded = (
                clean_base64
                + padding
            )

            bytes_data = (
                base64.b64decode(
                    padded,
                    validate=False
                )
            )

            decoded_str = (
                bytes_data.decode(
                    "utf-8",
                    errors="ignore"
                )
            )

            if decoded_str.strip():

                break

        except Exception:

            continue

    if decoded_str:

        # ----------------------------------------------
        # Base64 → YAML
        # ----------------------------------------------

        try:

            data = yaml.safe_load(
                decoded_str
            )

            if (
                isinstance(data, dict)
                and
                "proxies" in data
            ):

                print(
                    "【识别成功】当前模板为："
                    "Base64 编码的 YAML 格式。"
                )

                return data

        except Exception:

            pass

        # ----------------------------------------------
        # Base64 → URI
        # ----------------------------------------------

        proxies = []

        for line in (
            decoded_str.splitlines()
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
                f"【识别成功】当前文件为："
                f"Base64 编码的链接订阅，"
                f"成功提取 "
                f"{len(proxies)} 个有效节点。"
            )

            return {

                "proxies":
                    proxies,

                "proxy-groups":
                    [],

                "rules":
                    []
            }

    print(
        "【解析失败】无法解析模板。"
    )

    return {}


def adapt_node_for_test(
    node: dict,
    server: str,
    port: int
) -> dict:

    """
    测试版核心。

    这里只做两件事：

        1. server → IP
        2. port   → 测试端口

    其它参数全部尽可能保持原模板。

    特别是：

        SNI
        Host
        WS Path
        UUID
        password
        fingerprint
        ALPN

    不主动修改。

    这就是本次实验的核心。
    """

    new_node = copy.deepcopy(
        node
    )

    # --------------------------------------------------
    # 1. 直接替换连接地址
    # --------------------------------------------------

    new_node["server"] = (
        server
    )

    # --------------------------------------------------
    # 2. 替换端口
    # --------------------------------------------------

    new_node["port"] = (
        port
    )

    # --------------------------------------------------
    # 3. TLS 端口处理
    # --------------------------------------------------

    is_tls_port = (
        port in [
            443,
            8443,
            2053,
            2083,
            2087,
            2096,
        ]
    )

    if is_tls_port:

        new_node["tls"] = True

        new_node[
            "skip-cert-verify"
        ] = True

        # ----------------------------------------------
        # 如果原节点已经存在 SNI，
        # 一律保持原 SNI。
        # ----------------------------------------------

        domain = (
            node.get(
                "servername"
            )
            or
            node.get(
                "sni"
            )
            or
            node.get(
                "host"
            )
        )

        if not domain:

            if (
                "ws-opts"
                in node
            ):

                domain = (
                    node.get(
                        "ws-opts",
                        {}
                    )
                    .get(
                        "headers",
                        {}
                    )
                    .get(
                        "Host"
                    )
                )

        if domain:

            new_node[
                "servername"
            ] = domain

    else:

        # ------------------------------------------------
        # 80 为明文 HTTP
        # ------------------------------------------------

        new_node[
            "tls"
        ] = False

        new_node[
            "skip-cert-verify"
        ] = True

        # 只有非 TLS 端口才清掉 TLS 专用字段
        #
        # SNI / fingerprint / ALPN
        # 对 80 没有意义。
        #

        for key in [
            "client-fingerprint",
            "servername",
            "sni",
            "alpn",
            "reality-opts",
            "fingerprint",
            "flow",
        ]:

            new_node.pop(
                key,
                None
            )

    # --------------------------------------------------
    # 4. WS 参数
    #
    # Host 和 Path 保持模板。
    # --------------------------------------------------

    if (
        "ws-opts"
        in new_node
    ):

        ws_opts = new_node.get(
            "ws-opts",
            {}
        )

        path_val = (
            ws_opts.get(
                "path"
            )
            or
            "/?ed=2560"
        )

        clean_ws = {

            "path":
                path_val
        }

        host = None

        if isinstance(
            ws_opts.get(
                "headers"
            ),
            dict
        ):

            host = (
                ws_opts[
                    "headers"
                ].get(
                    "Host"
                )
            )

        # ----------------------------------------------
        # 如果原 WS Host 存在，
        # 保持原值。
        # ----------------------------------------------

        if not host:

            host = (
                node.get(
                    "servername"
                )
                or
                node.get(
                    "sni"
                )
                or
                node.get(
                    "host"
                )
            )

        if host:

            clean_ws[
                "headers"
            ] = {

                "Host":
                    host
            }

        new_node[
            "ws-opts"
        ] = clean_ws

    # --------------------------------------------------
    # 5. 删除旧 host 字段
    # --------------------------------------------------

    new_node.pop(
        "host",
        None
    )

    # --------------------------------------------------
    # 6. 测试名称
    # --------------------------------------------------

    base_name = node.get(
        "name",
        "node"
    )

    new_node[
        "name"
    ] = (
        f"{base_name} | "
        f"IP={server} | "
        f"PORT={port}"
    )

    return new_node


def generate_test_file(
    template_data: dict,
    cf_proxies: list,
    source_name: str,
    ip_source: str
) -> bool:

    """
    针对一个 IP 来源生成一个 YAML。
    """

    output_file = (
        f"{OUTPUT_PREFIX}"
        f"{source_name}.yaml"
    )

    print()
    print("=" * 65)

    print(
        f" 开始测试 IP 档位："
        f"{source_name}"
    )

    print("=" * 65)

    print(
        f"输入：{ip_source}"
    )

    print(
        f"输出：{output_file}"
    )

    # --------------------------------------------------
    # 获取 IP
    # --------------------------------------------------

    ips = fetch_ips(
        ip_source
    )

    if not ips:

        print(
            f"【跳过】{source_name} "
            f"没有获取到 IP。"
        )

        return False

    # --------------------------------------------------
    # 生成测试矩阵
    # --------------------------------------------------

    new_proxies = []

    print(
        "\n开始生成 IP × 端口测试节点..."
    )

    for base_proxy in cf_proxies:

        for ip in ips:

            for port in TEST_PORTS:

                if (
                    MAX_TOTAL_NODES
                    is not None
                    and
                    len(new_proxies)
                    >=
                    MAX_TOTAL_NODES
                ):

                    break

                new_node = (
                    adapt_node_for_test(
                        base_proxy,
                        ip,
                        port
                    )
                )

                new_proxies.append(
                    new_node
                )

            if (
                MAX_TOTAL_NODES
                is not None
                and
                len(new_proxies)
                >=
                MAX_TOTAL_NODES
            ):

                break

        if (
            MAX_TOTAL_NODES
            is not None
            and
            len(new_proxies)
            >=
            MAX_TOTAL_NODES
        ):

            break

    print(
        f"\n最终生成测试节点："
        f"{len(new_proxies)}"
    )

    # --------------------------------------------------
    # 基于原始模板
    # --------------------------------------------------

    output_data = copy.deepcopy(
        template_data
    )

    output_data[
        "proxies"
    ] = new_proxies

    optimized_names = [
        p["name"]
        for p in new_proxies
    ]

    output_data[
        "proxy-groups"
    ] = [

        {
            "name":
                "CF-Port-Test",

            "type":
                "select",

            "proxies":
                optimized_names,
        }
    ]

    output_data[
        "rules"
    ] = [
        "MATCH,CF-Port-Test"
    ]

    # --------------------------------------------------
    # 保存
    # --------------------------------------------------

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

    print(
        f"\n测试文件生成成功："
        f"{output_file}"
    )

    # --------------------------------------------------
    # 统计
    # --------------------------------------------------

    print(
        "\n测试矩阵："
    )

    print(
        f"  IP 文件："
        f"{source_name}"
    )

    print(
        f"  测试 IP："
        f"{len(ips)}"
    )

    print(
        f"  CF 节点模板："
        f"{len(cf_proxies)}"
    )

    print(
        f"  测试端口："
        f"{len(TEST_PORTS)}"
    )

    print(
        f"  理论数量："
        f"{len(cf_proxies)} × "
        f"{len(ips)} × "
        f"{len(TEST_PORTS)}"
    )

    print(
        f"  实际生成："
        f"{len(new_proxies)}"
    )

    # --------------------------------------------------
    # 打印前 10 个
    # --------------------------------------------------

    print(
        "\n测试名称示例："
    )

    for node in new_proxies[:10]:

        print(
            f"  {node.get('name')}"
        )

    # --------------------------------------------------
    # 如果是 Trojan，额外显示关键参数
    # --------------------------------------------------

    if cf_proxies:

        first = cf_proxies[0]

        if first.get(
            "type"
        ) == "trojan":

            print(
                "\nTrojan 测试参数保持："
            )

            print(
                f"  SNI："
                f"{first.get('servername', '')}"
            )

            print(
                f"  WS Host："
                f"{first.get('ws-opts', {}).get('headers', {}).get('Host', '')}"
            )

            print(
                f"  WS Path："
                f"{first.get('ws-opts', {}).get('path', '')}"
            )

            print(
                f"  Password："
                f"{first.get('password', '')}"
            )

    return True


def main():

    print("=" * 65)

    print(
        " Cloudflare 多 IP 档位 × 多端口批量对照测试生成器"
    )

    print(
        " 直接替换 server 域名/IP，不修改正式生成器"
    )

    print("=" * 65)

    print(
        f"\n测试端口："
        f"{', '.join(map(str, TEST_PORTS))}"
    )

    print(
        f"每个来源最多测试 IP："
        f"{TEST_IP_LIMIT}"
    )

    print(
        f"每个输出文件最多生成节点："
        f"{MAX_TOTAL_NODES}"
    )

    print(
        "\n本次自动处理："
    )

    for source_name in IP_SOURCES:

        print(
            f"  {source_name}"
            f" → "
            f"{OUTPUT_PREFIX}"
            f"{source_name}.yaml"
        )

    print()

    # --------------------------------------------------
    # 加载模板
    # --------------------------------------------------

    template_data = (
        universal_load_subscription(
            TEMPLATE_FILE
        )
    )

    if not template_data:

        return

    all_proxies = (
        template_data.get(
            "proxies",
            []
        )
    )

    if not all_proxies:

        print(
            "模板中没有节点。"
        )

        return

    # --------------------------------------------------
    # 找 CF 节点
    # --------------------------------------------------

    cf_proxies = [

        p
        for p in all_proxies
        if is_cf_node(p)
    ]

    print(
        f"\n模板总节点："
        f"{len(all_proxies)}"
    )

    print(
        f"识别到 CF 节点："
        f"{len(cf_proxies)}"
    )

    if not cf_proxies:

        print(
            "没有发现 CF 节点，退出。"
        )

        return

    # --------------------------------------------------
    # 显示原始节点
    # --------------------------------------------------

    print(
        "\n检测到的原始 CF 节点："
    )

    for proxy in cf_proxies:

        print(
            f"  [{proxy.get('type')}] "
            f"{proxy.get('name')} "
            f"→ "
            f"{proxy.get('server')}:"
            f"{proxy.get('port')}"
        )

    # --------------------------------------------------
    # 依次处理所有 IP 来源
    # --------------------------------------------------

    success_count = 0

    for (
        source_name,
        ip_source
    ) in IP_SOURCES.items():

        success = (
            generate_test_file(
                template_data,
                cf_proxies,
                source_name,
                ip_source
            )
        )

        if success:

            success_count += 1

    # --------------------------------------------------
    # 全部完成
    # --------------------------------------------------

    print()
    print("=" * 65)

    print(
        " 全部 IP 档位测试文件生成完成"
    )

    print("=" * 65)

    print(
        f"\n成功生成："
        f"{success_count} / "
        f"{len(IP_SOURCES)} 个文件"
    )

    print(
        "\n输出文件："
    )

    for source_name in IP_SOURCES:

        output_file = (
            f"{OUTPUT_PREFIX}"
            f"{source_name}.yaml"
        )

        print(
            f"  {output_file}"
        )

    print()

    print(
        "核心测试逻辑："
    )

    print(
        "  原 server 域名 → Cloudflare IP"
    )

    print(
        "  原 SNI → 保持不变"
    )

    print(
        "  原 WS Host → 保持不变"
    )

    print(
        "  原 WS Path → 保持不变"
    )

    print(
        "  原 UUID/password → 保持不变"
    )

    print(
        "  原其它协议参数 → 尽量保持不变"
    )

    print()

    print(
        "以后无需修改原 gem.yaml，"
    )

    print(
        "直接运行本脚本即可重新生成全部测试档位。"
    )


if __name__ == "__main__":

    main()
