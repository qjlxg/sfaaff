#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
逐文件真实测试套娃节点（支持跳过已测 + 最终自动合并）
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
INPUT_PATTERN = "cf_nest_*.yaml"
RESULT_DIR = Path("test_results")
LOG_FILE = RESULT_DIR / "test_log.txt"
FINAL_ALIVE_FILE = RESULT_DIR / "cf_nest_alive_all.yaml"   # 最终合并文件
XRAY_BIN = "xray"
TEST_URL = "http://www.gstatic.com/generate_204"
TIMEOUT = 7
MAX_WORKERS = 5
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
        futures = {executor.submit(test_one, p, i): p for i, p in enumerate(proxies)}
        for fut in as_completed(futures):
            tested += 1
            ok, proxy, elapsed = fut.result()
            name = (proxy.get("name") or "unknown")[:55]
            if ok:
                alive.append(proxy)
                print(f"[{tested}/{total}] ✅ {elapsed:.1f}s  {name}")
            else:
                if tested % 100 == 0 or tested == total:
                    print(f"[{tested}/{total}] 进度... 当前存活 {len(alive)}")

    stats = {
        "file": yaml_path.name,
        "total": total,
        "alive": len(alive),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return alive, stats


def save_result(yaml_path: Path, alive: list, stats: dict):
    RESULT_DIR.mkdir(exist_ok=True)
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
        with open(alive_file, "w", encoding="utf-8") as f:
            yaml.dump({"proxies": [], "note": "no alive nodes"}, f, allow_unicode=True)
        print(f"本文件无存活节点，已记录：{alive_file}")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{stats['time']}] 文件: {stats['file']} | 总数: {stats['total']} | 存活: {stats['alive']}\n")
    print(f"日志已更新：{LOG_FILE}")


def merge_all_alive():
    """把所有 alive_*.yaml 合并成一个总文件"""
    alive_files = sorted(RESULT_DIR.glob("alive_*.yaml"))
    if not alive_files:
        print("没有找到任何存活结果文件，跳过合并")
        return

    all_proxies = []
    for f in alive_files:
        try:
            with open(f, encoding="utf-8") as fp:
                data = yaml.safe_load(fp) or {}
            proxies = data.get("proxies", [])
            if proxies:
                all_proxies.extend(proxies)
                print(f"  合并 {f.name}: +{len(proxies)} 个")
        except Exception as e:
            print(f"  读取 {f.name} 失败: {e}")

    if not all_proxies:
        print("合并后没有存活节点")
        return

    # 简单去重（按 name）
    seen = set()
    unique = []
    for p in all_proxies:
        name = p.get("name")
        if name and name not in seen:
            seen.add(name)
            unique.append(p)

    final = {
        "proxies": unique,
        "proxy-groups": [{
            "name": "CF-Nest-Alive-All",
            "type": "select",
            "proxies": [p["name"] for p in unique]
        }],
        "rules": ["MATCH,CF-Nest-Alive-All"]
    }
    with open(FINAL_ALIVE_FILE, "w", encoding="utf-8") as f:
        yaml.dump(final, f, allow_unicode=True, sort_keys=False, width=1000)

    print(f"\n最终合并完成：{FINAL_ALIVE_FILE}")
    print(f"去重后总存活节点：{len(unique)}")


def main():
    if not shutil.which(XRAY_BIN) and not Path(XRAY_BIN).exists():
        print(f"错误：找不到 {XRAY_BIN}")
        return

    files = sorted(Path(".").glob(INPUT_PATTERN))
    if not files:
        print(f"没有找到 {INPUT_PATTERN} 文件")
        return

    RESULT_DIR.mkdir(exist_ok=True)

    print(f"共发现 {len(files)} 个待测试文件")
    for f in files:
        print(f"  - {f.name}")

    for idx, fpath in enumerate(files, 1):
        result_file = RESULT_DIR / f"alive_{fpath.stem}.yaml"

        # ========== 自动跳过已测文件 ==========
        if result_file.exists():
            print(f"\n[{idx}/{len(files)}] ⏭ 跳过已测文件：{fpath.name}")
            continue

        print(f"\n\n>>>>>>> 进度：{idx}/{len(files)} <<<<<<<")
        alive, stats = test_single_file(fpath)
        save_result(fpath, alive, stats)
        print(f"文件 {fpath.name} 处理完成\n")

    print("\n" + "="*60)
    print("所有文件处理结束，开始合并结果...")
    merge_all_alive()
    print("="*60)


if __name__ == "__main__":
    main()