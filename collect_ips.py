import requests
from bs4 import BeautifulSoup
import argparse
from datetime import datetime
from collections import Counter
import csv
import json
import re

# ================= 配置区域 =================
TOP_N = 55
# ============================================


def get_content(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9'
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )
        response.raise_for_status()
        return response.content

    except Exception as e:
        print(f"获取失败 {url}: {str(e)}")
        return None


def is_valid_target(key):
    """
    校验核心目标（#号前的内容）：
    必须是合法的 IPv4、IPv6 或域名。
    """

    key = key.strip()

    if (
        not key
        or len(key) > 100
        or '<' in key
        or '>' in key
        or '{' in key
        or '}' in key
    ):
        return False

    ipv4_pattern = re.compile(
        r'^\d{1,3}(\.\d{1,3}){3}$'
    )

    ipv6_pattern = re.compile(
        r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        r'|^::$'
        r'|^(?:[0-9a-fA-F]{1,4}:){1,7}:$'
        r'|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$'
    )

    domain_pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}'
        r'(?<!-)'
        r'(\.[A-Za-z0-9-]{1,63})+$'
    )

    clean_ip = (
        key.split(':')[0]
        if ':' in key and not ipv6_pattern.match(key)
        else key
    )

    if (
        ipv4_pattern.match(clean_ip)
        or ipv6_pattern.match(key)
        or domain_pattern.match(clean_ip)
    ):
        return True

    return False


def parse_html(html, source_url=''):
    if not html:
        return []

    text_content = html.decode(
        'utf-8',
        errors='ignore'
    )

    # ========================================================
    # JSON
    # ========================================================
    try:
        data_json = json.loads(text_content)

        results = []

        def extract_ips_from_json(obj, parent_key='api'):

            if isinstance(obj, dict):

                ip = (
                    obj.get('ip')
                    or obj.get('IP')
                    or obj.get('address')
                )

                if (
                    ip
                    and isinstance(ip, str)
                    and is_valid_target(ip.strip())
                ):

                    score = (
                        obj.get('avgScore')
                        or obj.get('score')
                        or ''
                    )

                    score_str = (
                        f" [Score:{score}]"
                        if score
                        else ""
                    )

                    results.append(
                        f"{ip.strip()} #{parent_key}{score_str}"
                    )

                for k, v in obj.items():
                    extract_ips_from_json(
                        v,
                        parent_key=k
                    )

            elif isinstance(obj, list):

                for item in obj:
                    extract_ips_from_json(
                        item,
                        parent_key=parent_key
                    )

        extract_ips_from_json(data_json)

        if results:
            return list(dict.fromkeys(results))

    except Exception:
        pass

    # ========================================================
    # HTML 表格
    # ========================================================
    soup = BeautifulSoup(
        text_content,
        'html.parser'
    )

    table = soup.find('tbody')

    rows = (
        soup.select('tr')
        if not table
        else table.select('tr')
    )

    results = []

    for row in rows:

        cols = row.find_all('td')

        if len(cols) >= 2:

            ip_address = cols[1].text.strip()

            line_name = (
                cols[0].text.strip()
                if len(cols) > 0
                else "line"
            )

            data_center = (
                cols[-2].text.strip()
                if len(cols) >= 6
                else "dc"
            )

            item = (
                f"{ip_address} "
                f"#{line_name}-{data_center}"
            )

            if is_valid_target(ip_address):
                results.append(item)

    # ========================================================
    # HTML 中没有表格时，直接匹配 IPv4
    # ========================================================
    if not results:

        ip_matches = re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            text_content
        )

        for ip in ip_matches:

            if is_valid_target(ip):
                results.append(
                    f"{ip} #text-match"
                )

    return list(dict.fromkeys(results))


def parse_txt(content):

    if not content:
        return []

    text = content.decode(
        'utf-8',
        errors='ignore'
    )

    results = []

    for line in text.splitlines():

        line = line.strip()

        if not line or line.startswith('#'):
            continue

        parts = line.split('#', 1)

        key = parts[0].strip()

        if is_valid_target(key):
            results.append(line)

    return results


# ============================================================
# 合并输出
# ============================================================

def save_to_file(
    data,
    filename,
    exclude_items=None,
    top_n=100
):
    """
    保存全部去重后的数据。

    当前逻辑：
    - 不排除 Top N
    - merged_all_ips.txt 保存全部有效 IP
    - 每个 IP 只保留一条完整记录
    """

    if not data:
        print(
            f"无有效数据可保存到 {filename}"
        )
        return

    exclude_items = exclude_items or set()

    seen_keys = set()

    unique_data = []

    for item in data:

        key = item.split('#')[0].strip()

        # 保留原有参数兼容性。
        # 当前统计逻辑不主动排除 Top N。
        if exclude_items and key in exclude_items:
            continue

        if key not in seen_keys:

            seen_keys.add(key)

            unique_data.append(item)

    unique_data.sort()

    with open(
        filename,
        'w',
        encoding='utf-8'
    ) as f:

        if unique_data:
            f.write(
                '\n'.join(unique_data)
                + '\n'
            )

    print(
        f"成功保存 {len(unique_data)} 条"
        f"去重数据到 {filename}"
    )

    with open(
        f"{filename}.log",
        'a',
        encoding='utf-8'
    ) as log:

        log.write(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - "
            f"保存 {len(unique_data)} 条去重数据\n"
        )


# ============================================================
# 统计与输出
# ============================================================

def save_stats_files(
    all_raw_data,
    base_output_name,
    top_n=100
):
    """
    统计所有 IP 出现次数，并输出不同频率等级的数据。

    输出：

      ip_stats.csv
          全部 IP 完整统计

      top_ips.txt
          出现次数最高的 Top N

      ip_frequency.txt
          IP + 精确出现次数

      ips_1only.txt
          恰好出现 1 次

      ips_2only.txt
          恰好出现 2 次

      ips_3only.txt
          恰好出现 3 次

      ips_4only.txt
          恰好出现 4 次

      ips_5plus.txt
          出现 5 次及以上

    注意：

      这里的“出现次数”严格按照
      all_raw_data 中同一个核心 IP
      出现的次数统计。

      1only / 2only / 3only / 4only / 5plus
      五个文件互相绝对不重复。

      当前不改变抓取、解析逻辑。
    """

    if not all_raw_data:

        print("无数据可用于统计")

        return set()

    # ========================================================
    # IP -> 第一条完整记录
    # ========================================================

    key_to_full_item = {}

    normalized_keys = []

    for item in all_raw_data:

        item = item.strip()

        if not item:
            continue

        key = item.split('#')[0].strip()

        normalized_keys.append(key)

        # 如果之前没有这个 IP，
        # 保存当前完整记录。
        #
        # 如果已有记录，但之前没有 #，
        # 当前有 #，则用当前完整记录替换。
        if (
            key not in key_to_full_item
            or (
                '#' in item
                and '#' not in key_to_full_item[key]
            )
        ):
            key_to_full_item[key] = item

    # ========================================================
    # 精确统计出现次数
    # ========================================================

    counter = Counter(normalized_keys)

    # ========================================================
    # 按出现次数从高到低排序
    # 次数相同则按 IP / key 字符串排序
    # ========================================================

    sorted_stats = sorted(
        counter.items(),
        key=lambda x: (-x[1], x[0])
    )

    # ========================================================
    # 基础统计
    # ========================================================

    total_raw = len(normalized_keys)

    total_unique = len(counter)

    print()
    print("=" * 60)
    print("统计结果")
    print("=" * 60)

    print(
        f"原始有效记录数 : {total_raw}"
    )

    print(
        f"去重后 IP 数    : {total_unique}"
    )

    # 精确输出 1～5 次及以上
    for threshold in [1, 2, 3, 4, 5]:

        count = sum(
            1
            for _, freq in sorted_stats
            if freq >= threshold
        )

        print(
            f"出现 >= {threshold} 次 : {count}"
        )

    print(
        f"Top {top_n}              : "
        f"{min(top_n, total_unique)}"
    )

    print("=" * 60)

    # ========================================================
    # 1. 完整 CSV
    # ========================================================

    csv_filename = "ip_stats.csv"

    try:

        with open(
            csv_filename,
            'w',
            encoding='utf-8-sig',
            newline=''
        ) as f:

            writer = csv.writer(f)

            writer.writerow([
                '排名',
                '数据主体内容',
                '出现次数',
                '完整数据'
            ])

            for idx, (item, count) in enumerate(
                sorted_stats,
                1
            ):

                full_item = (
                    key_to_full_item.get(
                        item,
                        item
                    )
                )

                writer.writerow([
                    idx,
                    item,
                    count,
                    full_item
                ])

        print(
            f"成功保存完整统计 CSV 到 "
            f"{csv_filename}"
        )

    except Exception as e:

        print(
            f"保存统计CSV文件失败: "
            f"{str(e)}"
        )

    # ========================================================
    # 2. Top N
    # ========================================================

    top_filename = "top_ips.txt"

    top_slice = sorted_stats[:top_n]

    try:

        top_data = [
            key_to_full_item[item[0]]
            for item in top_slice
            if item[0] in key_to_full_item
        ]

        with open(
            top_filename,
            'w',
            encoding='utf-8'
        ) as f:

            if top_data:
                f.write(
                    '\n'.join(top_data)
                    + '\n'
                )

        print(
            f"成功保存出现次数最多的前 "
            f"{top_n} 个到 {top_filename}"
        )

    except Exception as e:

        print(
            f"保存 {top_filename} 文件失败: "
            f"{str(e)}"
        )

    # ========================================================
    # 3. IP + 精确出现次数
    # ========================================================

    frequency_filename = (
        "ip_frequency.txt"
    )

    try:

        with open(
            frequency_filename,
            'w',
            encoding='utf-8'
        ) as f:

            for item, count in sorted_stats:

                f.write(
                    f"{item} #{count}\n"
                )

        print(
            f"成功保存 IP 出现次数列表到 "
            f"{frequency_filename}"
        )

    except Exception as e:

        print(
            f"保存 {frequency_filename} 文件失败: "
            f"{str(e)}"
        )

    # ========================================================
    # 4. 绝对互斥频率分档
    #
    # 1only  = 恰好 1 次
    # 2only  = 恰好 2 次
    # 3only  = 恰好 3 次
    # 4only  = 恰好 4 次
    # 5plus  = 5 次及以上
    #
    # 同一个 IP 只会进入其中一个文件。
    # ========================================================

    frequency_files = {
        1: "ips_1only.txt",
        2: "ips_2only.txt",
        3: "ips_3only.txt",
        4: "ips_4only.txt",
        5: "ips_5plus.txt",
    }

    for threshold, filename in frequency_files.items():

        if threshold < 5:

            selected = [
                key_to_full_item[item]
                for item, count in sorted_stats
                if count == threshold
                and item in key_to_full_item
            ]

        else:

            selected = [
                key_to_full_item[item]
                for item, count in sorted_stats
                if count >= 5
                and item in key_to_full_item
            ]

        try:

            with open(
                filename,
                'w',
                encoding='utf-8'
            ) as f:

                if selected:

                    f.write(
                        '\n'.join(selected)
                        + '\n'
                    )

            if threshold < 5:

                print(
                    f"出现 = {threshold} 次: "
                    f"{len(selected)} 条 -> "
                    f"{filename}"
                )

            else:

                print(
                    f"出现 >= 5 次: "
                    f"{len(selected)} 条 -> "
                    f"{filename}"
                )

        except Exception as e:

            print(
                f"保存 {filename} 文件失败: "
                f"{str(e)}"
            )

    # ========================================================
    # 5. 返回 Top N key 集合
    #
    # 保留返回值，兼容原 main()
    # ========================================================

    top_keys = {
        item[0]
        for item in top_slice
    }

    return top_keys


# ============================================================
# 主程序
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            '多源聚合采集Cloudflare IP地址'
            '并统计出现频率'
        )
    )

    parser.add_argument(
        '--output',
        default='merged_all_ips.txt',
        help='自定义合并输出文件名'
    )

    args = parser.parse_args()

    all_data = []

    # ========================================================
    # 数据源
    #
    # 保持原来的数据源不变
    # ========================================================

    sources = [
        (
            'https://www.wetest.vip/page/cloudflare/address_v4.html',
            'html'
        ),
        (
            'https://api.uouin.com/cloudflare.html',
            'html'
        ),
        (
            'https://addressesapi.090227.xyz/CloudFlareYes',
            'html'
        ),
        (
            'https://vps789.com/public/sum/cfIpApi',
            'json'
        ),
        (
            'https://cf.junzhen.qzz.io/full_ips.txt',
            'txt'
        ),
        (
            'https://cf.junzhen.qzz.io/full_ips_bj.txt',
            'txt'
        ),
        (
            'https://raw.githubusercontent.com/joname1/BestCFip/refs/heads/main/ipv4.txt',
            'txt'
        ),
        (
            'https://raw.githubusercontent.com/vpspig/cfip_best/refs/heads/main/ipv4.txt',
            'txt'
        ),
        (
            'https://raw.githubusercontent.com/yuanxiawan/cfipv4db/refs/heads/main/high_score_ips.txt',
            'txt'
        )
    ]

    # ========================================================
    # 开始采集
    # ========================================================

    for url, stype in sources:

        print(
            f"正在采集: {url}"
        )

        content = get_content(url)

        if not content:
            continue

        if stype == 'txt':

            parsed = parse_txt(
                content
            )

        else:

            parsed = parse_html(
                content,
                url
            )

        print(
            f"  -> 有效获取到 "
            f"{len(parsed)} 条"
        )

        all_data.extend(parsed)

    # ========================================================
    # 统计
    # ========================================================

    top_keys = save_stats_files(
        all_data,
        args.output,
        top_n=TOP_N
    )

    # ========================================================
    # 最终合并文件
    #
    # 明确保存全部去重 IP。
    #
    # 不排除 Top 55
    # 不排除任何频率等级
    # ========================================================

    save_to_file(
        all_data,
        args.output,
        exclude_items=set(),
        top_n=TOP_N
    )


if __name__ == '__main__':
    main()