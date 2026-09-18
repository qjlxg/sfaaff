import os
import re

# 路径配置
SOURCE_FILE = "dd.txt"
OUTPUT_FILE = "clean_ip_list.txt"

def main():
    if not os.path.exists(SOURCE_FILE):
        print(f"❌ 错误: 找不到源文件 {SOURCE_FILE}")
        return

    ip_port_list = []

    with open(SOURCE_FILE, "r", encoding="utf-8") as f:
        for line in f:
            # 精确匹配 @ 符号后面、冒号前面的 IP，以及后面的端口数字
            match = re.search(r"@([\d\.]+):(\d+)", line)
            if match:
                ip, port = match.groups()
                ip_port_list.append(f"{ip}:{port}")

    # 去重并排序
    unique_ip_ports = sorted(list(set(ip_port_list)))

    if not unique_ip_ports:
        print("❌ 未能从文件中提取到任何有效的 IP:端口。")
        return

    # 写入文件
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(unique_ip_ports) + "\n")

    print(f"🎉 成功提取 {len(unique_ip_ports)} 个纯净 IP:端口，已保存至 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
