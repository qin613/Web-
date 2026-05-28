"""SQL注入检测引擎"""
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import requests


@dataclass
class SQLiVulnerability:
    url: str
    param: str
    method: str
    technique: str  # error, boolean, time, union
    payload: str
    evidence: str
    severity: str = "high"

    def to_dict(self):
        return {
            "url": self.url,
            "param": self.param,
            "method": self.method,
            "technique": self.technique,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
            "type": "SQL Injection",
        }


# SQL错误特征（覆盖主流数据库）
SQL_ERROR_PATTERNS = [
    # MySQL
    r"SQL syntax.*?MySQL",
    r"Warning.*?mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
    r"MySqlClient\.",
    r"com\.mysql\.jdbc",
    r"Unclosed quotation mark after the character string",
    # PostgreSQL
    r"PostgreSQL.*?ERROR",
    r"Warning.*?\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError",
    r"org\.postgresql\.util\.PSQLException",
    r"ERROR:\s+syntax error at or near",
    # MSSQL
    r"Driver.*? SQL[\-\_\ ]*Server",
    r"OLE DB.*? SQL Server",
    r"(\W|\A)SQL Server[^&lt;&quot;]+Driver",
    r"Warning.*?mssql_",
    r"(\W|\A)SQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
    r"System\.Data\.SqlClient\.SqlException",
    r"Unclosed quotation mark after the character string",
    r"Microsoft SQL Native Client error",
    # Oracle
    r"\bORA-[0-9][0-9][0-9][0-9]",
    r"Oracle error",
    r"Oracle.*?Driver",
    r"Warning.*?\Woci_",
    r"Warning.*?\Wora_",
    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*?sqlite_",
    r"Warning.*?SQLite3::",
    r"\[SQLITE_ERROR\]",
    r"SQLite error",
    # 通用
    r"SQL syntax error",
    r"sql error",
    r"Syntax error.*?in query expression",
    r"Unexpected end of command",
    r"Statement could not be compiled",
    r"Data type mismatch",
    r"Microsoft Access.*?Driver",
    r"JET Database Engine",
    r"Access Database Engine",
]

SQL_ERROR_REGEX = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE | re.DOTALL)


class SQLiScanner:
    """SQL注入扫描器"""

    def __init__(self, timeout: int = 10, delay: float = 0):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })

    # ── Payloads ──────────────────────────────────────────────

    @staticmethod
    def _error_payloads():
        return [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1\" --",
            "') OR ('1'='1",
            "1' ORDER BY 100--",
            "1 UNION SELECT NULL--",
            "')) OR 1=1--",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "1; SELECT 1--",
        ]

    @staticmethod
    def _boolean_payloads():
        return [
            ("' OR '1'='1", "' OR '1'='2"),
            ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("1 OR 1=1", "1 OR 1=2"),
            ("') OR ('1'='1", "') OR ('1'='2"),
            ("1 AND 1=1--", "1 AND 1=2--"),
        ]

    @staticmethod
    def _time_payloads():
        return [
            "' OR SLEEP(3)--",
            "\" OR SLEEP(3)--",
            "1; WAITFOR DELAY '0:0:3'--",
            "' OR pg_sleep(3)--",
            "1; SELECT SLEEP(3)",
            "1' AND SLEEP(3) AND '1'='1",
            "1 AND BENCHMARK(5000000,SHA1('test'))",
            "'; SELECT BENCHMARK(5000000,SHA1('test'))--",
        ]

    @staticmethod
    def _union_payloads():
        payloads = []
        for i in range(1, 11):
            nulls = ",".join(["NULL"] * i)
            payloads.append(f"' UNION SELECT {nulls}--")
            payloads.append(f"\" UNION SELECT {nulls}--")
            payloads.append(f"' UNION ALL SELECT {nulls}--")
        return payloads

    # ── 检测方法 ──────────────────────────────────────────────

    def _make_request(self, url, method, param, value, data=None, cookies=None):
        """发送请求并返回(response, elapsed_seconds)"""
        try:
            if method.upper() == "GET":
                params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
                params[param] = value
                base = urllib.parse.urlsplit(url)._replace(query="").geturl()
                start = time.time()
                resp = self.session.get(
                    base, params=params, timeout=self.timeout,
                    allow_redirects=True, cookies=cookies
                )
                elapsed = time.time() - start
                return resp, elapsed
            else:
                post_data = dict(data) if data else {}
                post_data[param] = value
                start = time.time()
                resp = self.session.post(
                    url, data=post_data, timeout=self.timeout,
                    allow_redirects=True, cookies=cookies
                )
                elapsed = time.time() - start
                return resp, elapsed
        except requests.RequestException:
            return None, 0

    def _get_baseline(self, url, method, data=None):
        """获取正常响应基线"""
        try:
            if method.upper() == "GET":
                resp = self.session.get(url, timeout=self.timeout)
            else:
                resp = self.session.post(url, data=data or {}, timeout=self.timeout)
            return resp
        except requests.RequestException:
            return None

    def _check_sql_error(self, text):
        """检查响应中是否包含SQL错误信息"""
        match = SQL_ERROR_REGEX.search(text)
        if match:
            return match.group(0)
        return None

    def scan_param(self, url, param, method="GET", data=None):
        """对单个参数进行SQL注入检测"""
        vulnerabilities = []

        # 1) 报错注入检测
        vuln = self._detect_error(url, param, method, data)
        if vuln:
            vulnerabilities.append(vuln)
            return vulnerabilities  # 已确认存在注入，跳过其他检测

        # 2) 布尔盲注检测
        vuln = self._detect_boolean(url, param, method, data)
        if vuln:
            vulnerabilities.append(vuln)
            return vulnerabilities

        # 3) 时间盲注检测
        vuln = self._detect_time(url, param, method, data)
        if vuln:
            vulnerabilities.append(vuln)
            return vulnerabilities

        # 4) UNION注入检测
        vuln = self._detect_union(url, param, method, data)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_error(self, url, param, method, data):
        """报错注入检测"""
        for payload in self._error_payloads():
            resp, _ = self._make_request(url, method, param, payload, data)
            if resp is None:
                continue
            error = self._check_sql_error(resp.text)
            if error:
                return SQLiVulnerability(
                    url=url, param=param, method=method,
                    technique="error-based", payload=payload,
                    evidence=f"SQL错误: {error[:200]}", severity="high"
                )
            if self.delay:
                time.sleep(self.delay)
        return None

    def _detect_boolean(self, url, param, method, data):
        """布尔盲注检测"""
        baseline = self._get_baseline(url, method, data)
        if baseline is None:
            return None
        baseline_len = len(baseline.text)

        for true_payload, false_payload in self._boolean_payloads():
            true_resp, _ = self._make_request(url, method, param, true_payload, data)
            false_resp, _ = self._make_request(url, method, param, false_payload, data)
            if true_resp is None or false_resp is None:
                continue

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            # 真条件响应与基线相似，假条件响应差异大
            if (abs(true_len - baseline_len) < 50 and
                    abs(false_len - baseline_len) > 100):
                return SQLiVulnerability(
                    url=url, param=param, method=method,
                    technique="boolean-blind", payload=f"TRUE: {true_payload} / FALSE: {false_payload}",
                    evidence=f"真条件长度={true_len}, 假条件长度={false_len}, 基线长度={baseline_len}",
                    severity="high"
                )
            if self.delay:
                time.sleep(self.delay)
        return None

    def _detect_time(self, url, param, method, data):
        """时间盲注检测"""
        # 先获取正常响应时间
        _, normal_time = self._make_request(url, method, param, "1", data)
        threshold = normal_time + 2.5  # 正常时间 + 2.5秒阈值

        for payload in self._time_payloads():
            resp, elapsed = self._make_request(url, method, param, payload, data)
            if resp is None:
                continue
            if elapsed > threshold and elapsed > 3:
                return SQLiVulnerability(
                    url=url, param=param, method=method,
                    technique="time-blind", payload=payload,
                    evidence=f"响应时间={elapsed:.2f}s, 正常时间={normal_time:.2f}s",
                    severity="high"
                )
            if self.delay:
                time.sleep(self.delay)
        return None

    def _detect_union(self, url, param, method, data):
        """UNION注入检测"""
        baseline = self._get_baseline(url, method, data)
        if baseline is None:
            return None

        for payload in self._union_payloads():
            resp, _ = self._make_request(url, method, param, payload, data)
            if resp is None:
                continue
            # 检查是否返回了正常内容（UNION成功时不报错且内容变化）
            error = self._check_sql_error(resp.text)
            if not error and len(resp.text) > 0:
                # 检查是否有NULL被输出
                if "NULL" in resp.text or len(resp.text) != len(baseline.text):
                    return SQLiVulnerability(
                        url=url, param=param, method=method,
                        technique="union-based", payload=payload,
                        evidence=f"UNION查询成功, 响应长度变化: {len(baseline.text)} -> {len(resp.text)}",
                        severity="high"
                    )
            if self.delay:
                time.sleep(self.delay)
        return None
