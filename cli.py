"""CLI命令行入口 - Web漏洞扫描器"""
import argparse
import sys
import os

from scanner.scanner import WebScanner, ScanConfig
from scanner.reporter import Reporter


def main():
    parser = argparse.ArgumentParser(
        description="Web漏洞扫描器 - SQL注入 & XSS自动化检测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python cli.py -u http://example.com
  python cli.py -u http://example.com --scan-type sqli --threads 10
  python cli.py -u http://example.com --depth 3 --output reports/
        """
    )

    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("--scan-type", choices=["all", "sqli", "xss"],
                        default="all", help="扫描类型 (默认: all)")
    parser.add_argument("--threads", type=int, default=5,
                        help="并发线程数 (默认: 5)")
    parser.add_argument("--depth", type=int, default=2,
                        help="爬取深度 (默认: 2)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="请求超时时间/秒 (默认: 10)")
    parser.add_argument("--delay", type=float, default=0,
                        help="请求间隔/秒 (默认: 0)")
    parser.add_argument("-o", "--output", default="reports",
                        help="报告输出目录 (默认: reports/)")

    args = parser.parse_args()

    target_url = args.url
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    config = ScanConfig(
        target_url=target_url,
        scan_type=args.scan_type,
        threads=args.threads,
        depth=args.depth,
        timeout=args.timeout,
        delay=args.delay,
    )

    print("=" * 60)
    print("  Web漏洞扫描器")
    print("=" * 60)
    print(f"  目标: {config.target_url}")
    print(f"  类型: {config.scan_type}")
    print(f"  线程: {config.threads} | 深度: {config.depth} | 超时: {config.timeout}s")
    print("=" * 60)
    print()

    scanner = WebScanner(config)

    # 实时打印进度
    def on_progress(msg):
        print(f"  [*] {msg}")

    def on_vuln(vuln):
        d = vuln.to_dict()
        severity_colors = {
            "high": "\033[91m",    # 红
            "medium": "\033[93m",  # 黄
            "low": "\033[96m",     # 青
            "info": "\033[94m",    # 蓝
        }
        reset = "\033[0m"
        color = severity_colors.get(d["severity"], "")
        print(f"\n  {color}[!] 发现漏洞: {d['type']} ({d['technique']}){reset}")
        print(f"      URL: {d['url']}")
        print(f"      参数: {d['param']} ({d['method']})")
        print(f"      Payload: {d['payload']}")
        print(f"      证据: {d['evidence'][:100]}")
        print()

    scanner.on_progress(on_progress)
    scanner.on_vulnerability(on_vuln)

    result = scanner.scan()

    # 打印结果摘要
    print()
    print("=" * 60)
    print("  扫描结果摘要")
    print("=" * 60)
    print(f"  扫描目标数: {result.targets_scanned}")
    print(f"  扫描耗时: {result.scan_time:.1f}s")
    print(f"  漏洞总数: {len(result.vulnerabilities)}")

    high = sum(1 for v in result.vulnerabilities if v.severity == "high")
    medium = sum(1 for v in result.vulnerabilities if v.severity == "medium")
    low = sum(1 for v in result.vulnerabilities if v.severity in ("low", "info"))

    if high:
        print(f"  \033[91m高危: {high}\033[0m")
    if medium:
        print(f"  \033[93m中危: {medium}\033[0m")
    if low:
        print(f"  \033[96m低危/信息: {low}\033[0m")

    print("=" * 60)

    # 保存报告
    reporter = Reporter()
    report_path = reporter.save_report(result, args.output)
    print(f"\n  报告已保存: {report_path}")
    print()

    return 0 if not result.vulnerabilities else 1


if __name__ == "__main__":
    sys.exit(main())
