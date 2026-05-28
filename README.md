# Web漏洞扫描器

一款基于Python的Web漏洞自动化扫描工具，支持SQL注入和XSS漏洞检测，提供Web界面和命令行两种使用方式。

> 仅供授权安全测试和教育学习使用，请勿用于非法用途。

## 功能特性

**SQL注入检测**
- 报错注入 - 基于数据库错误信息识别
- 布尔盲注 - 通过响应差异判断
- 时间盲注 - 通过响应延时判断
- UNION注入 - 自动探测列数
- 内置多组绕WAF的Payload

**XSS检测**
- 反射型XSS检测
- 20+种Payload（script/img/svg/事件处理器/伪协议等）
- 多编码绕过测试（HTML实体/URL/Unicode/大小写混合）

**Web爬虫**
- 自动递归爬取目标网站
- 发现页面链接、表单、URL参数
- 可配置爬取深度和页面数量

**报告输出**
- 生成独立HTML报告
- 按高危/中危/低危分级展示
- 包含漏洞详情、Payload和证据

## 安装

```bash
git clone https://github.com/qin613/Web-.git
cd web-vuln-scanner
pip install -r requirements.txt
```

依赖：requests、beautifulsoup4、flask、lxml

## 使用方式

### Web界面

```bash
python app.py
```

浏览器访问 `http://127.0.0.1:5000`

- 仪表板查看扫描历史
- 新建扫描页配置目标和参数
- 实时查看扫描进度和漏洞发现
- 在线查看HTML报告

### 命令行

```bash
# 完整扫描（SQL注入 + XSS）
python cli.py -u http://target.com

# 仅SQL注入检测，10线程，爬取深度3
python cli.py -u http://target.com --scan-type sqli --threads 10 --depth 3

# 仅XSS检测，自定义报告输出目录
python cli.py -u http://target.com --scan-type xss -o my_reports/
```

**CLI参数：**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-u, --url` | 目标URL（必填） | - |
| `--scan-type` | 扫描类型：all / sqli / xss | all |
| `--threads` | 并发线程数 | 5 |
| `--depth` | 爬取深度 | 2 |
| `--timeout` | 请求超时（秒） | 10 |
| `--delay` | 请求间隔（秒） | 0 |
| `-o, --output` | 报告输出目录 | reports/ |

## 项目结构

```
├── app.py              # Flask Web应用入口
├── cli.py              # CLI命令行入口
├── requirements.txt    # Python依赖
├── scanner/
│   ├── crawler.py      # Web爬虫
│   ├── sqli.py         # SQL注入检测引擎
│   ├── xss.py          # XSS检测引擎
│   ├── scanner.py      # 扫描编排器
│   └── reporter.py     # HTML报告生成
├── templates/          # Flask模板
│   ├── index.html      # 仪表板
│   ├── scan.html       # 扫描页
│   └── report.html     # 报告页
└── static/style.css    # 样式
```

## 检测原理

### SQL注入

| 技术 | 原理 |
|------|------|
| 报错注入 | 注入特殊字符，检测响应中的SQL错误信息（覆盖MySQL/PostgreSQL/MSSQL/SQLite/Oracle） |
| 布尔盲注 | 分别发送真/假条件，对比响应长度差异 |
| 时间盲注 | 注入延时语句（SLEEP/WAITFOR DELAY），检测响应时间差 |
| UNION注入 | 逐步增加列数，尝试UNION SELECT获取数据 |

### XSS

注入唯一标记检测参数值是否被反射，然后发送多种XSS Payload，检查是否在响应中原样输出（未编码），区分安全编码和危险反射。

## 测试靶场

以下公开靶场可用于测试（请在合法授权下使用）：

- http://testphp.vulnweb.com
- http://testasp.vulnweb.com
- DVWA（Damn Vulnerable Web Application）

## 免责声明

本工具仅供安全研究人员在获得授权的情况下进行安全测试使用。使用者应遵守所在地区的法律法规，因使用本工具造成的一切后果由使用者自行承担。

## License

MIT
