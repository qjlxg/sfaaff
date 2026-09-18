#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_nodes.py
多源代理节点订阅聚合脚本（支持明文 / Base64 / Clash YAML）
按协议分类保存，每 500 节点自动拆分，支持并行、去重、增量跳过
仅保留适合优选 IP 套娃的 Cloudflare 自建节点（workers.dev / pages.dev / bpb 等）
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse, parse_qs

import requests
import yaml

# ======================== 配置区域 ========================
# 远程订阅源列表（一行一个 URL）
SOURCES_URL = "https://raw.githubusercontent.com/qjlxg/results/refs/heads/main/sources.txt"
NODES_DIR = Path("nodes")                               # 所有生成文件放这里
STATS_CSV = NODES_DIR / "stats.csv"                     # 每次运行统计
CHANGELOG = NODES_DIR / "changelog.md"                  # 变化记录
HASH_FILE = NODES_DIR / "source_hashes.json"            # 内容哈希（用于跳过）
MAX_WORKERS = 12                                        # 并行线程数
NODES_PER_FILE = 500                                    # 每个文件最多节点数
REQUEST_TIMEOUT = 25                                    # 单个源超时秒数
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ---------- Cloudflare 自建节点过滤（宽松模式）----------
# 只保留这些协议
CF_PROTOCOLS = {"vless", "trojan", "vmess"}

# Cloudflare 常用端口
CF_PORTS = {
    80, 443, 2052, 2053, 2082, 2083, 2086, 2087,
    2095, 2096, 8080, 8443, 8880,
}

# 域名特征（小写匹配）
CF_DOMAIN_KEYWORDS = (
    "workers.dev",
    "pages.dev",
)

# 节点名 / 备注 / host / sni 关键词（小写匹配）
CF_NAME_KEYWORDS = (
    "bpb",
    "worker",
    "workers",
    "cloudflare",
    "pages.dev",
    "workers.dev",
    "优选",
    "套娃",
    "cf-",
    "cf_",
    "-cf",
    "_cf",
    "vpslook",
)

# 北京时间
BEIJING_TZ = timezone(timedelta(hours=8))


# ======================== 工具函数 ========================
def now_beijing() -> str:
    return datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def safe_b64decode(data: str) -> Optional[str]:
    """尝试 Base64 解码，失败返回 None"""
    data = data.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        decoded = base64.b64decode(data, validate=False)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    return printable / len(text) > 0.85


# ======================== 订阅源读取 ========================
def load_subscriptions() -> List[str]:
    """从远程 sources.txt 拉取订阅源列表"""
    print(f"[信息] 正在获取远程订阅源列表: {SOURCES_URL}")
    try:
        resp = requests.get(
            SOURCES_URL,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        text = resp.text
    except Exception as e:
        print(f"[错误] 无法获取远程订阅源列表: {e}")
        sys.exit(1)

    urls = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    print(f"[信息] 共加载 {len(urls)} 个订阅源")
    return urls


# ======================== 网络拉取 ========================
def fetch_url(url: str) -> Tuple[str, Optional[str], Optional[str]]:
    """返回: (url, content, error)"""
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
        try:
            text = resp.content.decode("utf-8")
        except UnicodeDecodeError:
            text = resp.content.decode("utf-8", errors="ignore")
        return url, text, None
    except Exception as e:
        return url, None, str(e)


# ======================== 节点提取核心 ========================
SHARE_LINK_PATTERN = re.compile(
    r"(?:^|[\s\"'<>])("
    r"(?:ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic|wireguard|wg)://[^\s\"'<>]+"
    r")",
    re.IGNORECASE | re.MULTILINE,
)


def extract_share_links(text: str) -> List[str]:
    """从任意文本中提取所有分享链接"""
    links = []
    for m in SHARE_LINK_PATTERN.finditer(text):
        link = m.group(1).rstrip(".,;)]}>'\"")
        if link:
            links.append(link)
    return links


def parse_clash_yaml(text: str) -> List[str]:
    """解析 Clash / Mihomo YAML，提取 proxies 并尽量转成分享链接"""
    links = []
    try:
        text = text.lstrip("\ufeff")
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            return links
        proxies = data.get("proxies") or data.get("Proxy") or []
        if not isinstance(proxies, list):
            return links

        for p in proxies:
            if not isinstance(p, dict):
                continue
            link = clash_proxy_to_share_link(p)
            if link:
                links.append(link)
    except Exception:
        pass
    return links


def clash_proxy_to_share_link(p: dict) -> Optional[str]:
    """把 Clash 节点字典尽量转成标准分享链接（简化版，覆盖主流）"""
    t = (p.get("type") or "").lower()
    name = p.get("name") or "node"
    server = p.get("server") or p.get("servername") or ""
    port = p.get("port")
    if not server or not port:
        return None

    try:
        if t == "ss":
            method = p.get("cipher") or p.get("method") or "aes-256-gcm"
            password = p.get("password") or ""
            userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            return f"ss://{userinfo}@{server}:{port}#{name}"

        elif t == "ssr":
            return None

        elif t == "vmess":
            conf = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": str(port),
                "id": p.get("uuid") or p.get("id") or "",
                "aid": str(p.get("alterId") or p.get("alterid") or 0),
                "scy": p.get("cipher") or "auto",
                "net": p.get("network") or "tcp",
                "type": p.get("type") or "none",
                "host": (p.get("ws-opts") or {}).get("headers", {}).get("Host") or p.get("host") or "",
                "path": (p.get("ws-opts") or {}).get("path") or p.get("path") or "",
                "tls": "tls" if p.get("tls") else "",
                "sni": p.get("servername") or p.get("sni") or "",
            }
            raw = json.dumps(conf, ensure_ascii=False, separators=(",", ":"))
            b64 = base64.b64encode(raw.encode()).decode()
            return f"vmess://{b64}"

        elif t == "vless":
            uuid = p.get("uuid") or ""
            params = []
            if p.get("tls"):
                params.append("security=tls")
            if p.get("flow"):
                params.append(f"flow={p['flow']}")
            if p.get("network"):
                params.append(f"type={p['network']}")
            if p.get("servername") or p.get("sni"):
                params.append(f"sni={p.get('servername') or p.get('sni')}")
            if p.get("host"):
                params.append(f"host={p['host']}")
            query = "&".join(params)
            return f"vless://{uuid}@{server}:{port}?{query}#{name}"

        elif t == "trojan":
            password = p.get("password") or ""
            params = []
            if p.get("sni") or p.get("servername"):
                params.append(f"sni={p.get('sni') or p.get('servername')}")
            query = "&".join(params)
            return f"trojan://{password}@{server}:{port}?{query}#{name}"

        elif t in ("hysteria", "hysteria2", "hy2"):
            auth = p.get("password") or p.get("auth") or ""
            protocol = "hysteria2" if t != "hysteria" else "hysteria"
            return f"{protocol}://{auth}@{server}:{port}#{name}"

        elif t == "tuic":
            uuid = p.get("uuid") or ""
            password = p.get("password") or ""
            return f"tuic://{uuid}:{password}@{server}:{port}#{name}"

    except Exception:
        return None
    return None


def detect_and_parse(content: str) -> List[str]:
    """自动检测格式并解析出所有分享链接"""
    content = content.strip()
    if not content:
        return []

    links = extract_share_links(content)
    if len(links) >= 3:
        return links

    decoded = safe_b64decode(content)
    if decoded and is_mostly_printable(decoded):
        links = extract_share_links(decoded)
        if links:
            return links
        if "proxies:" in decoded or "Proxy:" in decoded:
            return parse_clash_yaml(decoded)

    if "proxies:" in content or "Proxy:" in content or content.lstrip().startswith("{"):
        return parse_clash_yaml(content)

    if not links:
        pure = re.sub(r"^#.*$", "", content, flags=re.MULTILINE).strip()
        decoded = safe_b64decode(pure)
        if decoded:
            links = extract_share_links(decoded)
            if not links and ("proxies:" in decoded or "Proxy:" in decoded):
                links = parse_clash_yaml(decoded)

    return links


def normalize_link(link: str) -> str:
    """简单规范化，用于去重（去掉 # 后面的备注差异）"""
    link = link.strip()
    if "#" in link:
        return link.split("#", 1)[0]
    return link


def get_protocol(link: str) -> str:
    """从分享链接提取协议名"""
    m = re.match(r"^([a-z0-9]+)://", link, re.IGNORECASE)
    if not m:
        return "unknown"
    proto = m.group(1).lower()
    if proto == "hy2":
        return "hysteria2"
    if proto == "wg":
        return "wireguard"
    return proto


# ======================== CF 自建节点过滤 ========================
def _text_has_cf_keyword(text: str) -> bool:
    """文本中是否包含 CF 相关关键词"""
    if not text:
        return False
    low = text.lower()
    for kw in CF_DOMAIN_KEYWORDS:
        if kw in low:
            return True
    for kw in CF_NAME_KEYWORDS:
        if kw in low:
            return True
    return False


def _parse_vmess_info(link: str) -> dict:
    """解析 vmess:// 得到 add/port/ps/host/sni 等"""
    try:
        b64 = link.split("://", 1)[1]
        if "#" in b64:
            b64 = b64.split("#", 1)[0]
        raw = safe_b64decode(b64)
        if not raw:
            return {}
        return json.loads(raw)
    except Exception:
        return {}


def is_cf_style_node(link: str) -> bool:
    """
    判断是否为适合优选 IP 套娃的 Cloudflare 自建节点（宽松模式）
    条件（满足其一即可，同时协议必须是 vless/trojan/vmess）：
    1. 协议为 vless / trojan / vmess
    2. 域名含 workers.dev / pages.dev
       或 节点名/备注/host/sni 含 bpb、worker、cf、cloudflare、pages、优选、套娃 等
    3. 端口尽量落在 Cloudflare 常用端口（解析不到端口时不卡死）
    """
    proto = get_protocol(link)
    if proto not in CF_PROTOCOLS:
        return False

    full = link
    remark = ""
    host = ""
    port = None
    sni_host = ""

    # 提取备注
    if "#" in link:
        main, remark = link.split("#", 1)
        remark = unquote(remark)
    else:
        main = link

    # ----- vmess 特殊处理 -----
    if proto == "vmess":
        info = _parse_vmess_info(main)
        host = str(info.get("add") or "")
        try:
            port = int(info.get("port") or 0) or None
        except Exception:
            port = None
        remark = remark or str(info.get("ps") or "")
        sni_host = str(info.get("host") or info.get("sni") or "")
    else:
        # vless://uuid@host:port?params#remark
        # trojan://pass@host:port?params#remark
        try:
            # 去掉协议前缀
            rest = main.split("://", 1)[1]
            # 用户信息 @ 主机
            if "@" in rest:
                rest = rest.split("@", 1)[1]
            # host:port?query
            host_port = rest.split("?", 1)[0]
            if ":" in host_port:
                host_part, port_part = host_port.rsplit(":", 1)
                host = host_part
                try:
                    port = int(port_part)
                except Exception:
                    port = None
            else:
                host = host_port

            # 解析 query 里的 host / sni
            if "?" in rest:
                qs = rest.split("?", 1)[1]
                params = parse_qs(qs)
                for key in ("host", "sni", "servername", "peer"):
                    if key in params and params[key]:
                        sni_host = params[key][0]
                        break
        except Exception:
            pass

    # 端口检查：解析到了端口且不在常用列表 → 仍可通过关键词放行，但优先端口匹配
    port_ok = (port is None) or (port in CF_PORTS)

    # 关键词 / 域名检查
    domain_ok = _text_has_cf_keyword(host) or _text_has_cf_keyword(sni_host)
    name_ok = _text_has_cf_keyword(remark) or _text_has_cf_keyword(full)

    # 宽松：域名或名称命中即可；端口作为辅助（不强制）
    if domain_ok or name_ok:
        return True

    # 如果只有端口对 + 协议对，但完全没有 CF 特征，则不要（避免普通机场节点）
    return False


def filter_cf_nodes(links: List[str]) -> List[str]:
    """过滤出 CF 自建风格节点"""
    kept = []
    for link in links:
        if is_cf_style_node(link):
            kept.append(link)
    return kept


# ======================== 主流程 ========================
def load_previous_hashes() -> Dict[str, str]:
    if HASH_FILE.exists():
        try:
            with open(HASH_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_hashes(hashes: Dict[str, str]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    with open(HASH_FILE, "w", encoding="utf-8") as f:
        json.dump(hashes, f, ensure_ascii=False, indent=2)


def process_one_source(url: str, prev_hashes: Dict[str, str]) -> dict:
    """处理单个订阅源，返回统计信息"""
    result = {
        "url": url,
        "count": 0,
        "status": "ok",
        "error": "",
        "skipped": False,
        "hash": "",
        "links": [],
    }

    url, content, err = fetch_url(url)
    if err or content is None:
        result["status"] = "error"
        result["error"] = err or "empty content"
        return result

    h = content_hash(content)
    result["hash"] = h

    if prev_hashes.get(url) == h:
        result["skipped"] = True
        result["status"] = "skipped"
        return result

    links = detect_and_parse(content)
    seen = set()
    unique = []
    for link in links:
        norm = normalize_link(link)
        if norm not in seen:
            seen.add(norm)
            unique.append(link)

    result["count"] = len(unique)
    result["links"] = unique
    return result


def save_nodes_by_protocol(all_links: List[str]):
    """按协议建子目录 + 每 500 个拆分文件"""
    NODES_DIR.mkdir(parents=True, exist_ok=True)

    for item in NODES_DIR.iterdir():
        if item.is_dir():
            for f in item.glob("*.txt"):
                f.unlink()
            try:
                item.rmdir()
            except OSError:
                pass

    groups: Dict[str, List[str]] = {}
    for link in all_links:
        proto = get_protocol(link)
        groups.setdefault(proto, []).append(link)

    total_files = 0
    for proto, links in sorted(groups.items()):
        if not links:
            continue
        unique = list(dict.fromkeys(links))
        proto_dir = NODES_DIR / proto
        proto_dir.mkdir(parents=True, exist_ok=True)

        for i in range(0, len(unique), NODES_PER_FILE):
            chunk = unique[i : i + NODES_PER_FILE]
            idx = i // NODES_PER_FILE + 1
            filename = proto_dir / f"{idx:03d}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk) + "\n")
            total_files += 1
            print(f"  → 写入 {proto}/{filename.name}  ({len(chunk)} 个节点)")

    print(f"[完成] 共生成 {total_files} 个文件，覆盖 {len(groups)} 种协议")


def write_stats(results: List[dict]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    file_exists = STATS_CSV.exists()
    with open(STATS_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "url", "count", "status", "error", "skipped"])
        ts = now_beijing()
        for r in results:
            writer.writerow([
                ts,
                r["url"],
                r["count"],
                r["status"],
                r.get("error", ""),
                r.get("skipped", False),
            ])


def write_changelog(results: List[dict], prev_hashes: Dict[str, str]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append(f"## 运行时间：{now_beijing()} (北京时间)\n")

    updated = [r for r in results if not r.get("skipped") and r["status"] == "ok"]
    skipped = [r for r in results if r.get("skipped")]
    errors = [r for r in results if r["status"] == "error"]

    lines.append(f"- 成功更新：{len(updated)} 个源")
    lines.append(f"- 内容未变跳过：{len(skipped)} 个源")
    lines.append(f"- 拉取失败：{len(errors)} 个源\n")

    if updated:
        lines.append("### 本次有更新的源\n")
        for r in updated:
            lines.append(f"- `{r['url']}` → **{r['count']}** 个节点")
        lines.append("")

    if errors:
        lines.append("### 失败的源\n")
        for r in errors:
            lines.append(f"- `{r['url']}` : {r.get('error', '')}")
        lines.append("")

    old = ""
    if CHANGELOG.exists():
        old = CHANGELOG.read_text(encoding="utf-8")
    with open(CHANGELOG, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n---\n\n" + old)


def main():
    print(f"========== collect_nodes 开始运行 {now_beijing()} ==========")
    NODES_DIR.mkdir(parents=True, exist_ok=True)

    urls = load_subscriptions()
    prev_hashes = load_previous_hashes()

    results = []
    all_links: List[str] = []
    seen_global: Set[str] = set()

    print(f"[信息] 开始并行拉取（workers={MAX_WORKERS}）...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(process_one_source, url, prev_hashes): url for url in urls}
        for future in as_completed(future_map):
            r = future.result()
            results.append(r)
            status = r["status"]
            if r.get("skipped"):
                print(f"  [跳过] {r['url'][:60]}... (内容未变化)")
            elif status == "error":
                print(f"  [失败] {r['url'][:60]}... → {r.get('error')}")
            else:
                print(f"  [成功] {r['url'][:60]}... → {r['count']} 节点")
                for link in r["links"]:
                    norm = normalize_link(link)
                    if norm not in seen_global:
                        seen_global.add(norm)
                        all_links.append(link)

    new_hashes = dict(prev_hashes)
    for r in results:
        if r["hash"] and r["status"] in ("ok", "skipped"):
            new_hashes[r["url"]] = r["hash"]
    save_hashes(new_hashes)

    print(f"\n[信息] 全局去重后共 {len(all_links)} 个有效节点")

    # ---------- 过滤 Cloudflare 自建节点 ----------
    cf_links = filter_cf_nodes(all_links)
    print(f"[信息] 过滤后保留 CF 自建风格节点：{len(cf_links)} 个")

    save_nodes_by_protocol(cf_links)
    write_stats(results)
    write_changelog(results, prev_hashes)

    print(f"========== 运行结束 {now_beijing()} ==========")


if __name__ == "__main__":
    main()
