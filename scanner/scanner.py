"""扫描编排器：调度爬虫和检测模块"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from .crawler import Crawler, ScanTarget
from .sqli import SQLiScanner, SQLiVulnerability
from .xss import XSSScanner, XSSVulnerability


@dataclass
class ScanConfig:
    """扫描配置"""
    target_url: str
    scan_type: str = "all"  # all / sqli / xss
    threads: int = 5
    depth: int = 2
    timeout: int = 10
    delay: float = 0


@dataclass
class ScanResult:
    """扫描结果"""
    target_url: str
    scan_type: str
    targets_scanned: int = 0
    vulnerabilities: list = field(default_factory=list)
    scan_time: float = 0
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self):
        return {
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "targets_scanned": self.targets_scanned,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_time": self.scan_time,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "vuln_count": len(self.vulnerabilities),
            "high_count": sum(1 for v in self.vulnerabilities if v.severity == "high"),
            "medium_count": sum(1 for v in self.vulnerabilities if v.severity == "medium"),
            "low_count": sum(1 for v in self.vulnerabilities if v.severity in ("low", "info")),
        }


class WebScanner:
    """Web漏洞扫描器主类"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.crawler = Crawler(
            timeout=config.timeout,
            max_depth=config.depth,
        )
        self.sqli_scanner = SQLiScanner(timeout=config.timeout, delay=config.delay)
        self.xss_scanner = XSSScanner(timeout=config.timeout, delay=config.delay)
        self._progress_callback: Optional[Callable] = None
        self._vuln_callback: Optional[Callable] = None
        self._running = True

    def on_progress(self, callback: Callable):
        """注册进度回调"""
        self._progress_callback = callback

    def on_vulnerability(self, callback: Callable):
        """注册发现漏洞回调"""
        self._vuln_callback = callback

    def stop(self):
        """停止扫描"""
        self._running = False

    def _report_progress(self, message: str):
        if self._progress_callback:
            self._progress_callback(message)

    def _report_vulnerability(self, vuln):
        if self._vuln_callback:
            self._vuln_callback(vuln)

    def _scan_target(self, target: ScanTarget):
        """扫描单个目标"""
        vulnerabilities = []

        # 对URL中的每个参数进行扫描
        if target.method == "GET" and target.params:
            for param in target.params:
                if not self._running:
                    break

                if self.config.scan_type in ("all", "sqli"):
                    try:
                        vulns = self.sqli_scanner.scan_param(
                            target.url, param, "GET"
                        )
                        for v in vulns:
                            vulnerabilities.append(v)
                            self._report_vulnerability(v)
                    except Exception:
                        pass

                if self.config.scan_type in ("all", "xss"):
                    try:
                        vulns = self.xss_scanner.scan_param(
                            target.url, param, "GET"
                        )
                        for v in vulns:
                            vulnerabilities.append(v)
                            self._report_vulnerability(v)
                    except Exception:
                        pass

        # 对表单进行扫描
        if target.method == "POST" and target.form_data:
            for param in target.form_data:
                if not self._running:
                    break

                if self.config.scan_type in ("all", "sqli"):
                    try:
                        vulns = self.sqli_scanner.scan_param(
                            target.form_action or target.url,
                            param, "POST", data=target.form_data
                        )
                        for v in vulns:
                            vulnerabilities.append(v)
                            self._report_vulnerability(v)
                    except Exception:
                        pass

                if self.config.scan_type in ("all", "xss"):
                    try:
                        vulns = self.xss_scanner.scan_param(
                            target.form_action or target.url,
                            param, "POST", data=target.form_data
                        )
                        for v in vulns:
                            vulnerabilities.append(v)
                            self._report_vulnerability(v)
                    except Exception:
                        pass

        return vulnerabilities

    def scan(self) -> ScanResult:
        """执行完整扫描"""
        result = ScanResult(
            target_url=self.config.target_url,
            scan_type=self.config.scan_type,
            started_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        start_time = time.time()

        self._report_progress(f"开始扫描目标: {self.config.target_url}")

        # 1) 爬取目标
        self._report_progress("阶段1: 爬取网站，发现扫描目标...")
        targets = self.crawler.crawl(
            self.config.target_url,
            progress_callback=self._report_progress
        )

        if not targets:
            self._report_progress("未发现可扫描的目标，请检查URL是否正确")
            result.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            result.scan_time = time.time() - start_time
            return result

        result.targets_scanned = len(targets)
        self._report_progress(f"阶段2: 开始扫描 {len(targets)} 个目标...")

        # 2) 并发扫描
        all_vulns = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_map = {
                executor.submit(self._scan_target, target): target
                for target in targets
            }

            completed = 0
            for future in as_completed(future_map):
                completed += 1
                target = future_map[future]
                try:
                    vulns = future.result()
                    all_vulns.extend(vulns)
                except Exception:
                    pass

                self._report_progress(
                    f"扫描进度: {completed}/{len(targets)} "
                    f"({completed * 100 // len(targets)}%)"
                )

        result.vulnerabilities = all_vulns
        result.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        result.scan_time = time.time() - start_time

        self._report_progress(
            f"扫描完成! 耗时 {result.scan_time:.1f}s, "
            f"发现 {len(all_vulns)} 个漏洞"
        )

        return result
