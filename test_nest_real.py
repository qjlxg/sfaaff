#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
逐文件真实测试套娃节点
一次只测一个 YAML 文件（最多 5000 节点），测完保存结果再测下一个
"""

import yaml
import json
import subprocess
import tempfile
import os
import time
import socket
import requests
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ===================== 配置 =====================
INPUT_PATTERN = "cf_nest_*.yaml"       # 要测试的文件
RESULT_DIR = Path("test_results")      # 结果保存目录
LOG_FILE = RESULT_DIR / "test_log.txt" # 总日志
XRAY_BIN = "xray"                      # xray 路径
TEST_URL = "http://www.gstatic.com/generate_204"
TIMEOUT = 7                            # 单节点超时（秒）
MAX_WORKERS = 5                        # 单文件内并发数（建议 4\~6）
# ===============================================


def find_free_port(start=20000):
    port = start
    while port < start + 800:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("无可用端口")


def clash_to_xray_outbound(proxy: dict):
    ptype = proxy.get("type", "").lower()
    server = proxy["server"]
    port = int(proxy["port"])

    def make_stream():
        stream = {
            "network": proxy.get("network", "ws"),
            "security": "tls" if proxy.get("tls") else "none",
        }
        if proxy.get("tls"):
            stream["tlsSettings"] = {
                "serverName": proxy.get("servername") or proxy.get("sni") or server,
                "allowInsecure": True
            }
        if proxy.get("network") == "ws":
            ws = proxy.get("ws-opts", {})
            stream["wsSettings"] = {
                "path": ws.get("path", "/"),
                "headers": ws.get("headers", {})
            }
        return stream

    if ptype == "trojan":
        return {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "password": proxy.get("password", "")
                }]
            },
            "streamSettings": make_stream()
        }
    elif ptype == "vless":
        return {
            "tag": "proxy",
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
            "streamSettings": make_stream()
        }
    elif ptype == "vmess":
        return {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": port,
                    "users": [{
                        "id": proxy.get("uuid"),
                        "alterId": proxy.get("alterId", 0),
                        "security": proxy.get("cipher", "auto")
                    }]
                }]
            },
            "streamSettings": make_stream()
        }
    return None


def test_one(proxy, idx):
    outbound = clash_to_xray_outbound(proxy)
    if not outbound:
        return False, proxy, 0.0

    port = find_free_port(20000 + (idx % 500))
    conf = {
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
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(conf, f)
            conf_file = f.name

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", conf_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(0.45)

        proxies = {
            "http": f"socks5://127.0.0.1:{port}",
            "https": f"socks5://127.0.0.1:{port}"
        }
        r = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
        ok = r.status_code in (200, 204)
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


def test_single_file(yaml_path: Path):
    """测试单个文件，返回存活列表和统计"""
    print(f"\n{'='*60}")
    print(f"开始测试文件：{yaml_path.name}")
    print(f"{'='*60}")

    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    proxies = data.get("proxies", [])
    total = len(proxies)
    print(f"本文件节点数：{total}")

    if total == 0:
        return [], {"total": 0, "alive": 0, "file": yaml_path.name}

    alive = []
    tested = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(test_one, p, i): p
            for i, p in enumerate(proxies)
        }
        for fut in as_completed(futures):
            tested += 1
            ok, proxy, elapsed = fut.result()
            name = (proxy.get("name") or "unknown")[:55]
            if ok:
                alive.append(proxy)
                print(f"[{tested}/{total}] ✅ {elapsed:.1f}s  {name}")
            else:
                # 失败也打印进度，但少刷屏
                if tested % 100 == 0 or tested == total:
                    print(f"[{tested}/{total}] 进度更新... 当前存活 {len(alive)}")

    stats = {
        "file": yaml_path.name,
        "total": total,
        "alive": len(alive),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return alive, stats


def save_result(yaml_path: Path, alive: list, stats: dict):
    """无论是否有存活节点，都保存结果"""
    RESULT_DIR.mkdir(exist_ok=True)

    # 1. 保存存活节点（如果有）
    stem = yaml_path.stem
    alive_file = RESULT_DIR / f"alive_{stem}.yaml"
    if alive:
        out = {
            "proxies": alive,
            "proxy-groups": [{
                "name": "Alive",
                "type": "select",
                "proxies": [p["name"] for p in alive]
            }],
            "rules": ["MATCH,Alive"]
        }
        with open(alive_file, "w", encoding="utf-8") as f:
            yaml.dump(out, f, allow_unicode=True, sort_keys=False, width=1000)
        print(f"存活节点已保存：{alive_file} （{len(alive)} 个）")
    else:
        # 即使没有存活，也写一个空标记文件，方便知道测过了
        with open(alive_file, "w", encoding="utf-8") as f:
            yaml.dump({"proxies": [], "note": "no alive nodes"}, f, allow_unicode=True)
        print(f"本文件无存活节点，已记录：{alive_file}")

    # 2. 写总日志
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{stats['time']}] 文件: {stats['file']} | "
                f"总数: {stats['total']} | 存活: {stats['alive']}\n")

    print(f"日志已更新：{LOG_FILE}")


def main():
    if not shutil.which(XRAY_BIN) and not Path(XRAY_BIN).exists():
        print(f"错误：找不到 {XRAY_BIN}，请先把 Xray 二进制放到当前目录或 PATH")
        return

    files = sorted(Path(".").glob(INPUT_PATTERN))
    if not files:
        print(f"当前目录没有找到 {INPUT_PATTERN} 文件")
        return

    print(f"共发现 {len(files)} 个待测试文件：")
    for f in files:
        print(f"  - {f.name}")

    RESULT_DIR.mkdir(exist_ok=True)

    for idx, fpath in enumerate(files, 1):
        print(f"\n\n>>>>>>> 进度：{idx}/{len(files)} <<<<<<<")
        alive, stats = test_single_file(fpath)
        save_result(fpath, alive, stats)
        print(f"文件 {fpath.name} 处理完成，准备下一个...\n")

    print("\n" + "="*60)
    print("全部文件测试完成！")
    print(f"结果目录：{RESULT_DIR}")
    print(f"总日志：{LOG_FILE}")
    print("="*60)


if __name__ == "__main__":
    main()