"""漏洞测试靶场 - 用于测试扫描器"""
import sqlite3
import os
from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)
DB_PATH = "test.db"

# 初始化数据库
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY, name TEXT, price REAL, description TEXT)''')

    # 插入测试数据
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        users = [("admin", "admin123", "admin@test.com"),
                 ("user1", "pass123", "user1@test.com"),
                 ("test", "test123", "test@test.com")]
        c.executemany("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", users)

        products = [("iPhone 15", 7999, "苹果最新手机"),
                    ("小米14", 3999, "性价比之王"),
                    ("华为Mate60", 6999, "国产旗舰")]
        c.executemany("INSERT INTO products (name, price, description) VALUES (?, ?, ?)", products)

    conn.commit()
    conn.close()

# 首页
@app.route("/")
def index():
    return '''
    <html>
    <head><title>漏洞测试靶场</title></head>
    <body>
        <h1>漏洞测试靶场</h1>
        <p>用于测试Web漏洞扫描器</p>
        <ul>
            <li><a href="/search?q=">搜索页面</a> (SQL注入 + XSS)</li>
            <li><a href="/login">登录页面</a> (SQL注入)</li>
            <li><a href="/comment">评论页面</a> (XSS)</li>
            <li><a href="/product?id=1">产品详情</a> (SQL注入)</li>
        </ul>
    </body>
    </html>
    '''

# 搜索功能 - 存在SQL注入和XSS
@app.route("/search")
def search():
    q = request.args.get("q", "")
    if not q:
        return '''
        <html>
        <head><title>搜索</title></head>
        <body>
            <h2>搜索商品</h2>
            <form action="/search" method="GET">
                <input type="text" name="q" placeholder="输入关键词">
                <button type="submit">搜索</button>
            </form>
        </body>
        </html>
        '''

    # SQL注入漏洞 - 直接拼接用户输入
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"

    try:
        c.execute(query)
        results = c.fetchall()
    except Exception as e:
        # 报错注入 - 错误信息直接返回
        return f"<html><body><h2>搜索错误</h2><p>SQL错误: {e}</p><p>查询: {query}</p></body></html>"

    conn.close()

    # XSS漏洞 - 搜索词直接输出，未转义
    html = f'''
    <html>
    <head><title>搜索结果</title></head>
    <body>
        <h2>搜索结果: {q}</h2>
        <p>查询语句: {query}</p>
        <table border="1">
            <tr><th>ID</th><th>名称</th><th>价格</th><th>描述</th></tr>
    '''
    for row in results:
        html += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td></tr>"

    html += '''
        </table>
        <br><a href="/search">返回搜索</a>
    </body>
    </html>
    '''
    return html

# 登录功能 - 存在SQL注入
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return '''
        <html>
        <head><title>登录</title></head>
        <body>
            <h2>用户登录</h2>
            <form action="/login" method="POST">
                <p>用户名: <input type="text" name="username"></p>
                <p>密码: <input type="password" name="password"></p>
                <button type="submit">登录</button>
            </form>
        </body>
        </html>
        '''

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # SQL注入漏洞 - 直接拼接
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    try:
        c.execute(query)
        user = c.fetchone()
    except Exception as e:
        return f"<html><body><h2>登录错误</h2><p>SQL错误: {e}</p></body></html>"
    finally:
        conn.close()

    if user:
        return f"<html><body><h2>登录成功</h2><p>欢迎, {username}!</p><p>邮箱: {user[3]}</p></body></html>"
    else:
        # XSS漏洞 - 用户名直接输出
        return f"<html><body><h2>登录失败</h2><p>用户 '{username}' 不存在或密码错误</p></body></html>"

# 评论功能 - 存储型XSS
@app.route("/comment", methods=["GET", "POST"])
def comment():
    comments = []
    if os.path.exists("comments.txt"):
        with open("comments.txt", "r", encoding="utf-8") as f:
            comments = f.read().strip().split("\n") if f.read().strip() else []

    if request.method == "POST":
        name = request.form.get("name", "")
        content = request.form.get("content", "")
        # 存储型XSS - 直接保存用户输入
        with open("comments.txt", "a", encoding="utf-8") as f:
            f.write(f"{name}|||{content}\n")
        return redirect(url_for("comment"))

    # 重新读取
    comments = []
    if os.path.exists("comments.txt"):
        with open("comments.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "|||" in line:
                    name, content = line.split("|||", 1)
                    comments.append((name, content))

    html = '''
    <html>
    <head><title>评论区</title></head>
    <body>
        <h2>评论区</h2>
        <form action="/comment" method="POST">
            <p>昵称: <input type="text" name="name"></p>
            <p>评论: <textarea name="content" rows="4" cols="50"></textarea></p>
            <button type="submit">提交评论</button>
        </form>
        <hr>
        <h3>评论列表</h3>
    '''
    for name, content in comments:
        # XSS漏洞 - 直接输出用户内容
        html += f"<div><b>{name}</b>: {content}</div><br>"

    html += '''
    </body>
    </html>
    '''
    return html

# 产品详情 - 存在SQL注入
@app.route("/product")
def product():
    product_id = request.args.get("id", "")

    if not product_id:
        return "<html><body><p>请提供产品ID</p><a href='/'>返回首页</a></body></html>"

    # SQL注入漏洞 - 直接拼接
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = f"SELECT * FROM products WHERE id={product_id}"

    try:
        c.execute(query)
        product = c.fetchone()
    except Exception as e:
        return f"<html><body><h2>查询错误</h2><p>错误: {e}</p><p>查询: {query}</p></body></html>"
    finally:
        conn.close()

    if product:
        # XSS漏洞 - 产品名直接输出
        return f'''
        <html>
        <head><title>{product[1]}</title></head>
        <body>
            <h2>{product[1]}</h2>
            <p>价格: ¥{product[2]}</p>
            <p>描述: {product[3]}</p>
            <br><a href="/">返回首页</a>
        </body>
        </html>
        '''
    else:
        return f"<html><body><p>产品 {product_id} 不存在</p><a href='/'>返回首页</a></body></html>"

if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  漏洞测试靶场已启动")
    print("  访问: http://127.0.0.1:8080")
    print("=" * 50)
    app.run(host="127.0.0.1", port=8080, debug=True)
