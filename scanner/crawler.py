"""Web爬虫：发现页面、表单、链接和参数"""
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup


@dataclass
class ScanTarget:
    """扫描目标"""
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)  # GET参数
    form_action: str = ""  # 表单action
    form_data: dict = field(default_factory=dict)  # 表单隐藏字段
    source: str = ""  # 来源：link / form / param

    def to_dict(self):
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "form_action": self.form_action,
            "form_data": self.form_data,
            "source": self.source,
        }


class Crawler:
    """Web爬虫"""

    def __init__(self, timeout: int = 10, max_depth: int = 2, max_pages: int = 50):
        self.timeout = timeout
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        self.visited = set()
        self.targets = []

    def _normalize_url(self, url, base_url):
        """规范化URL"""
        url = urljoin(base_url, url)
        parsed = urlparse(url)
        # 去掉fragment
        url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                          parsed.params, parsed.query, ""))
        return url

    def _is_same_domain(self, url, base_url):
        """检查是否同域"""
        return urlparse(url).netloc == urlparse(base_url).netloc

    def _extract_params(self, url):
        """从URL中提取查询参数"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        # 将列表值转为单值
        return {k: v[0] if v else "" for k, v in params.items()}

    def _extract_forms(self, soup, page_url):
        """从页面中提取表单"""
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            action_url = self._normalize_url(action, page_url) if action else page_url

            # 提取所有input字段
            inputs = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                value = inp.get("value", "")
                inp_type = inp.get("type", "text").lower()
                # 跳过submit按钮
                if inp_type in ("submit", "button", "image", "reset"):
                    continue
                inputs[name] = value

            if inputs:
                forms.append(ScanTarget(
                    url=action_url,
                    method=method,
                    form_action=action_url,
                    form_data=inputs,
                    source="form"
                ))
        return forms

    def _extract_links(self, soup, page_url, base_url):
        """从页面中提取链接"""
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            # 跳过锚点、javascript、mailto
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            url = self._normalize_url(href, page_url)
            if not self._is_same_domain(url, base_url):
                continue
            # 提取URL中的参数
            params = self._extract_params(url)
            links.append((url, params))
        return links

    def crawl(self, start_url, progress_callback=None):
        """
        爬取目标网站，发现所有可扫描的目标

        Args:
            start_url: 起始URL
            progress_callback: 进度回调函数 callback(message)

        Returns:
            list[ScanTarget]: 发现的扫描目标列表
        """
        self.visited = set()
        self.targets = []
        queue = [(start_url, 0)]  # (url, depth)
        base_url = start_url

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.pop(0)

            if url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)

            if progress_callback:
                progress_callback(f"正在爬取: {url} (深度 {depth})")

            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
            except requests.RequestException:
                continue

            soup = BeautifulSoup(resp.text, "lxml")

            # 提取URL参数作为GET扫描目标
            params = self._extract_params(url)
            if params:
                self.targets.append(ScanTarget(
                    url=url, method="GET", params=params, source="param"
                ))

            # 提取表单
            forms = self._extract_forms(soup, url)
            self.targets.extend(forms)

            # 提取链接并加入队列
            links = self._extract_links(soup, url, base_url)
            for link_url, link_params in links:
                if link_url not in self.visited:
                    queue.append((link_url, depth + 1))
                    # 带参数的链接也作为扫描目标
                    if link_params:
                        self.targets.append(ScanTarget(
                            url=link_url, method="GET",
                            params=link_params, source="link"
                        ))

        if progress_callback:
            progress_callback(f"爬取完成，发现 {len(self.targets)} 个扫描目标")

        return self.targets
