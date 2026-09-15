#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_nest_real.py
对套娃生成的 YAML 进行真实连通性测试（Xray-core）
支持断点续测：记录已完成的 yaml 文件，二次运行从上次位置继续
"""

import argparse
import yaml
import json
import subprocess
import tempfile
import os
import time
import socket
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
from typing import List, Dict, Tuple, Optional, Set

# ===================== 默认配置 =====================
DEFAULT_INPUT_GLOB = "cf_nest_*.yaml"
DEFAULT_OUTPUT = "cf_nest_alive.yaml"
PROGRESS_FILE = "test_nest_progress.json"   # 进度记录文件
XRAY_BIN = "xray"
TEST_URL = "http://www.gstatic.com/generate_204"
DEFAULT_TIMEOUT = 8
DEFAULT_WORKERS = 6
LOCAL_PORT_BASE = 18000
# ==================================================


def load_progress() -> Set[str]:
    """读取已完成的文件列表"""
    if not Path(PROGRESS_FILE).exists():
        return set()
    try:
        with open(PROGRESS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("completed", []))
    except Exception:
        return set()


def save_progress(completed: Set[str]):
    """保存进度"""
    data = {
        "completed": sorted(list(completed)),
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def find_free_port(start: int = LOCAL_PORT_BASE) -> int:
    port = start
    while port < start + 1000:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("找不到可用端口")


def clash_to_xray_outbound(proxy: dict) -> Optional[dict]:
    ptype = proxy.get("type", "").lower()
    server = proxy.get("server")
    port = int(proxy.get("port", 443))
    if not server:
        return None

    tag = "proxy"
    network = proxy.get("network", "ws")
    tls = bool(proxy.get("tls"))
    servername = proxy.get("servername") or proxy.get("sni") or server

    stream = {
        "network": network,
        "security": "tls" if tls else "none",
    }
    if tls:
        stream["tlsSettings"] = {
            "serverName": servername,
            "allowInsecure": True
        }

    if network == "ws":
        ws = proxy.get("ws-opts") or {}
        stream["wsSettings"] = {
            "path": ws.get("path", "/"),
            "headers": ws.get("headers") or {}
        }

    if ptype == "trojan":
        return {
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "password": proxy.get("password", ""),
                    "email": "t@t.tt"
                }]
            },
            "streamSettings": stream
        }
    elif ptype == "vless":
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": port,
                    "users": [{
                        "id": proxy.get("uuid"),
                        "encryption": "none",
                        "flow": proxy.get("flow", "")
                    }]
                }]
            },
            "streamSettings": stream
        }
    elif ptype == "vmess":
        return {
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": port,
                    "users": [{
                        "id": proxy.get("uuid"),
                        "alterId": int(proxy.get("alterId", 0)),
                        "security": proxy.get("cipher", "auto")
                    }]
                }]
            },
            "streamSettings": stream
        }
    return None


def test_one_proxy(proxy: dict, idx: int, timeout: int) -> Tuple[bool, dict, float]:
    outbound = clash_to_xray_outbound(proxy)
    if not outbound:
        return False, proxy, 0.0

    port = find_free_port(LOCAL_PORT_BASE + (idx % 300))
    xray_conf = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]
        }
    }

    conf_file = None
    proc = None
    start = time.time()
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(xray_conf, f, ensure_ascii=False)
            conf_file = f.name

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", conf_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(0.55)

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}"
        }
        resp = requests.get(TEST_URL, proxies=proxies, timeout=timeout)
        ok = resp.status_code in (200, 204)
        return ok, proxy, time.time() - start
    except Exception:
        return False, proxy, time.time() - start
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
        if conf_file and os.path.exists(conf_file):
            try:
                os.unlink(conf_file)
            except Exception:
                pass


def test_file(file_path: Path, workers: int, timeout: int) -> List[dict]:
    """测试单个 yaml 文件，返回存活节点"""
    with open(file_path, encoding="utf-8") as fp:
        data = yaml.safe_load(fp) or {}
    proxies = data.get("proxies", [])
    total = len(proxies)
    if total == 0:
        print(f"  {file_path.name} 没有节点，跳过")
        return []

    print(f"\n开始测试文件：{file_path.name}（{total} 个节点）")
    alive = []
    tested = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(test_one_proxy, proxy, i, timeout): proxy
            for i, proxy in enumerate(proxies)
        }
        for future in as_completed(futures):
            tested += 1
            ok, proxy, elapsed = future.result()
            name = str(proxy.get("name", "unknown"))[:70]
            if ok:
                alive.append(proxy)
                print(f"  [{tested}/{total}] ✅ 存活  {elapsed:.1f}s  {name}")
            else:
                print(f"  [{tested}/{total}] ❌ 失败  {elapsed:.1f}s  {name}")

    print(f"  文件 {file_path.name} 完成：存活 {len(alive)} / {total}")
    return alive


def save_alive(alive: List[dict], output: str):
    if not alive:
        print("没有存活节点，不生成文件")
        return
    data = {
        "proxies": alive,
        "proxy-groups": [{
            "name": "CF-Nest-Alive",
            "type": "select",
            "proxies": [p.get("name", f"node-{i}") for i, p in enumerate(alive)]
        }],
        "rules": ["MATCH,CF-Nest-Alive"]
    }
    with open(output, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False, width=1200)
    print(f"已保存存活节点到：{output}（共 {len(alive)} 个）")


def main():
    parser = argparse.ArgumentParser(description="真实测试套娃节点（支持断点续测）")
    parser.add_argument("--batch", help="只测试指定的单个 yaml 文件（GitHub Actions 用）")
    parser.add_argument("--input-glob", default=DEFAULT_INPUT_GLOB, help="本地全量时的文件匹配")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="最终合并输出文件名")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="并发数")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="单节点超时秒数")
    parser.add_argument("--force", action="store_true", help="忽略进度，强制重新测试所有文件")
    parser.add_argument("--reset-progress", action="store_true", help="清空进度记录后退出")
    args = parser.parse_args()

    # 重置进度
    if args.reset_progress:
        if Path(PROGRESS_FILE).exists():
            os.remove(PROGRESS_FILE)
            print(f"已清空进度文件：{PROGRESS_FILE}")
        else:
            print("进度文件不存在，无需清空")
        return

    # 检查 xray
    if not shutil.which(XRAY_BIN) and not Path(XRAY_BIN).exists():
        print(f"错误：找不到 Xray 可执行文件「{XRAY_BIN}」")
        print("请从 https://github.com/XTLS/Xray-core/releases 下载")
        exit(1)

    # 单文件模式（GitHub Actions 分批）
    if args.batch:
        file_path = Path(args.batch)
        if not file_path.exists():
            print(f"文件不存在：{args.batch}")
            return
        alive = test_file(file_path, args.workers, args.timeout)
        output = f"alive_{file_path.stem}.yaml"
        save_alive(alive, output)
        return

    # 本地全量模式 + 断点续测
    all_files = sorted(Path(".").glob(args.input_glob))
    if not all_files:
        print(f"没找到任何 {args.input_glob} 文件")
        return

    completed = set() if args.force else load_progress()
    print(f"进度文件：{PROGRESS_FILE}")
    print(f"已完成文件数：{len(completed)}")
    if completed:
        print("已完成：", ", ".join(sorted(completed)))

    pending = [f for f in all_files if f.name not in completed]
    if not pending:
        print("\n所有文件都已测试完成！如需重新测试请加 --force")
        return

    print(f"\n待测试文件（{len(pending)} 个）：")
    for f in pending:
        print(f"  - {f.name}")

    all_alive = []
    # 先把之前已经完成的存活结果尝试合并（如果有的话）
    # 这里简单处理：只合并本次新测的，最终输出本次+之前可用的话可自行扩展

    for file_path in pending:
        alive = test_file(file_path, args.workers, args.timeout)
        all_alive.extend(alive)

        # 标记该文件已完成
        completed.add(file_path.name)
        save_progress(completed)
        print(f"  进度已更新，当前已完成 {len(completed)} 个文件")

    # 最终合并输出
    print("\n" + "=" * 50)
    save_alive(all_alive, args.output)
    print("全部待测文件处理完成！")


if __name__ == "__main__":
    main()
