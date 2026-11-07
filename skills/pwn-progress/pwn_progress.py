#!/usr/bin/env python3
"""pwn.college 学习助手（纯 Python，无浏览器依赖）

用法:
    python pwn_progress.py setup                      # 交互式录入凭据 (DPAPI 加密存储)
    python pwn_progress.py                            # 所有有进度的 dojo 总览
    python pwn_progress.py <dojo>                     # 单个 dojo 的模块明细
    python pwn_progress.py modules <dojo>             # 模块列表(slug+进度)
    python pwn_progress.py challenges <dojo> <module> # 试题列表+解题状态
    python pwn_progress.py next <dojo>                # 按顺序找下一个未解试题
    python pwn_progress.py start <dojo> <module> <challenge>      # 启动试题 workspace
    python pwn_progress.py solve <dojo> <module> <challenge> <flag>  # 提交 flag
    python pwn_progress.py ssh [命令...]              # SSH 进入当前试题容器

配置目录: ~/.config/pwn-progress/ (可用环境变量 PWNC_CONF_DIR 覆盖)
    config.json      普通设置 (user_agent, ssh_key/ssh_user/ssh_host 可选)
    凭据存储按平台: Windows=DPAPI 加密 (标准库, 当前用户绑定);
    Linux/macOS=系统钥匙串 (需 pip install keyring); 无钥匙串时=0600 明文文件;
    也可用环境变量 PWNC_USER / PWNC_PASS (优先级最高, 适合无界面/cron)
    cookies.txt      登录会话缓存 (敏感, POSIX 下收紧为 0600)
"""
import base64
import ctypes
import html
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://pwn.college"
SESSION = os.environ.get("PWNC_SESSION", "pwnc")
CONF_DIR = os.environ.get("PWNC_CONF_DIR") or os.path.join(
    os.path.expanduser("~"), ".config", "pwn-progress")
CONF_PATH = os.path.join(CONF_DIR, "config.json")
CRED_PATH = os.path.join(CONF_DIR, "credentials.bin")
COOKIE_PATH = os.path.join(CONF_DIR, "cookies.txt")
# 兜底 UA: 无法从配置/浏览器取得时使用
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")


def load_config():
    if not os.path.exists(CONF_PATH):
        return {}
    with open(CONF_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg):
    os.makedirs(CONF_DIR, exist_ok=True)
    with open(CONF_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


# ---------- DPAPI 凭据加密 (Windows 原生, 当前用户自动解密, 换用户/机器不可解) ----------

class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _make_blob(data):
    buf = ctypes.create_string_buffer(data, len(data))
    return _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def dpapi_protect(data):
    if sys.platform != "win32":
        raise OSError("DPAPI 仅在 Windows 可用")
    pin, keep = _make_blob(data)
    pout = _BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(pin), "pwn-progress", None, None, None, 0, ctypes.byref(pout)):
        raise OSError("CryptProtectData 失败")
    out = ctypes.string_at(pout.pbData, pout.cbData)
    ctypes.windll.kernel32.LocalFree(pout.pbData)
    return out


def dpapi_unprotect(data):
    if sys.platform != "win32":
        raise OSError("DPAPI 仅在 Windows 可用")
    pin, _ = _make_blob(data)
    pout = _BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(pin), None, None, None, None, 0, ctypes.byref(pout)):
        raise OSError("CryptUnprotectData 失败 (凭据可能来自其他用户/机器)")
    out = ctypes.string_at(pout.pbData, pout.cbData)
    ctypes.windll.kernel32.LocalFree(pout.pbData)
    return out


# ---------- 凭据存储: 跨平台多后端 ----------
# Windows: DPAPI (标准库 ctypes, 当前用户绑定)
# Linux/macOS 桌面: keyring 包 (OS 钥匙串), 需 pip install keyring
# 无钥匙串的 headless: 环境变量 PWNC_USER/PWNC_PASS, 或 0600 权限明文文件(带警告)

SERVICE = "pwn-progress"


def _keyring_backend():
    try:
        import keyring
        keyring.get_password(SERVICE, "__probe__")
        return keyring
    except Exception:
        return None


def save_credentials(username, password):
    payload = json.dumps({"username": username, "password": password})
    os.makedirs(CONF_DIR, exist_ok=True)
    if sys.platform == "win32":
        blob = base64.b64encode(dpapi_protect(payload.encode())).decode()
        with open(CRED_PATH, "w", encoding="ascii") as f:
            f.write(blob)
        return "DPAPI 加密文件 (credentials.bin, 与当前 Windows 用户绑定)"
    kr = _keyring_backend()
    if kr:
        kr.set_password(SERVICE, "credentials", payload)
        return f"系统钥匙串 ({kr.get_keyring()})"
    with open(CRED_PATH, "w", encoding="utf-8") as f:
        f.write(payload)
    _restrict(CRED_PATH)
    return f"明文文件 {CRED_PATH} (权限已收紧; 建议 pip install keyring 以启用加密)"


def load_credentials(cfg):
    """优先级: 环境变量 > 加密存储 > config.json 明文(兼容旧版)"""
    env_u, env_p = os.environ.get("PWNC_USER"), os.environ.get("PWNC_PASS")
    if env_u and env_p:
        return {"username": env_u, "password": env_p}
    if sys.platform == "win32":
        if os.path.exists(CRED_PATH):
            with open(CRED_PATH, encoding="ascii") as f:
                blob = base64.b64decode(f.read().strip())
            try:
                return json.loads(dpapi_unprotect(blob))
            except OSError:
                sys.exit("凭据解密失败 (DPAPI 与当前 Windows 用户/机器绑定)。\n"
                         "请重新运行: python pwn_progress.py setup")
    else:
        kr = _keyring_backend()
        if kr:
            payload = kr.get_password(SERVICE, "credentials")
            if payload:
                return json.loads(payload)
        if os.path.exists(CRED_PATH):
            with open(CRED_PATH, encoding="utf-8") as f:
                return json.loads(f.read())
    if cfg.get("username") and cfg.get("password"):
        print("提示: 检测到 config.json 明文凭据, 建议运行 python pwn_progress.py setup 加密",
              file=sys.stderr)
        return {"username": cfg["username"], "password": cfg["password"]}
    return None


def _restrict(path):
    if sys.platform != "win32":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def cmd_setup():
    import getpass
    cfg = load_config()
    username = input("pwn.college 用户名: ").strip()
    password = getpass.getpass("pwn.college 密码 (输入不回显): ")
    if not username or not password:
        sys.exit("用户名/密码不能为空")
    where = save_credentials(username, password)
    removed = [k for k in ("username", "password") if cfg.pop(k, None) is not None]
    get_user_agent(cfg)  # 顺带补全并缓存 UA
    save_config(cfg)
    print(f"凭据已保存: {where}")
    if removed:
        print(f"已从 {CONF_PATH} 清除明文凭据字段")


def get_user_agent(cfg):
    """优先配置文件, 否则向已连接的浏览器取当前 UA 并缓存, 都不行缓存兜底值"""
    ua = cfg.get("user_agent")
    if ua:
        return ua
    try:
        out = subprocess.run(
            ["opencli", "browser", "eval", "navigator.userAgent", "--session", SESSION],
            capture_output=True, text=True, timeout=20).stdout
        ua = json.loads(out).get("data")
        if isinstance(ua, str) and ua.startswith("Mozilla/"):
            cfg["user_agent"] = ua
            save_config(cfg)
            return ua
    except Exception:
        pass
    cfg["user_agent"] = DEFAULT_UA  # 缓存兜底值, 避免每次启动都等待浏览器探测
    save_config(cfg)
    return DEFAULT_UA


def make_opener(cfg):
    jar = http.cookiejar.MozillaCookieJar(COOKIE_PATH)
    if os.path.exists(COOKIE_PATH):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except Exception:
            pass
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.addheaders = [
        ("User-Agent", get_user_agent(cfg)),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8"),
    ]
    return opener, jar


def fetch(opener, url, data=None, timeout=30):
    req = urllib.request.Request(url, data=data)
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            sys.exit(f"HTTP 403 (可能被 Cloudflare 拦截): 试试更新配置里的 user_agent\nURL: {url}")
        raise
    return resp.geturl(), resp.read().decode("utf-8", "replace")


def csrf_nonce(opener):
    """POST 类 API 需要页面里内嵌的 CSRF nonce (init 对象里的 'csrfNonce': "hex")"""
    _, page = fetch(opener, BASE + "/dojos")
    m = re.search(r"csrfNonce['\"]?\s*[:=]\s*['\"]([0-9a-f]+)['\"]", page)
    return m.group(1) if m else ""


def api_post(opener, path, payload, timeout=180):
    nonce = csrf_nonce(opener)
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode(),
        headers={"CSRF-Token": nonce, "Accept": "application/json",
                 "Content-Type": "application/json"}, method="POST")
    try:
        resp = opener.open(req, timeout=timeout)
        return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code} {e.reason}"}


def logged_in(opener):
    _, body = fetch(opener, BASE + "/pwncollege_api/v1/users/me")
    return body.lstrip().startswith("{") and '"id"' in body


def login(opener, jar, creds):
    if not creds:
        sys.exit("未登录且没有凭据。请先运行: python pwn_progress.py setup")
    _, page = fetch(opener, BASE + "/login")
    tag = re.search(r'<input[^>]*name="nonce"[^>]*>', page)
    if not tag:
        sys.exit("登录页解析失败 (可能被 Cloudflare 拦截), 请稍后重试")
    nonce = re.search(r'value="([^"]*)"', tag.group(0)).group(1)
    body = urllib.parse.urlencode({
        "name": creds["username"], "password": creds["password"],
        "nonce": nonce, "_submit": "Submit"}).encode()
    url, page = fetch(opener, BASE + "/login", data=body)
    if "/login" in url or 'name="nonce"' in page:
        hint = "用户名或密码错误" if "ncorrect" in page else "登录未生效"
        sys.exit(f"登录失败: {hint}")
    jar.save(ignore_discard=True, ignore_expires=True)
    _restrict(COOKIE_PATH)
    if not logged_in(opener):
        sys.exit("登录后验证失败 (users/me 无返回)")


def strip_tags(s):
    return html.unescape(re.sub(r"<[^>]+>", "", s)).strip()


def clean_stats(s):
    # textContent 会丢掉 <br>: "3 Hacking9 Modules232 Challenges" -> "3 Hacking 9 Modules 232 Challenges"
    return re.sub(r"(?<=[A-Za-z])(?=\d)", " ", s).strip()


def parse_dojos(page):
    rows = []
    for m in re.finditer(r'<a[^>]+href="(/dojo/[^"]+)"[^>]*>(.*?)</a>', page, re.S):
        block = m.group(2)
        title = re.search(r"<h4[^>]*>(.*?)</h4>", block, re.S)
        if not title:
            continue
        pct = re.search(r'progress-bar-text[^>]*>(\d+)%', block)
        stats = re.search(r"<p[^>]*>(.*?)</p>", block, re.S)
        rows.append({
            "dojo": strip_tags(title.group(1)),
            "url": m.group(1),
            "progress": f"{pct.group(1)}%" if pct else None,
            "stats": clean_stats(strip_tags(stats.group(1))) if stats else "",
        })
    return rows


def parse_modules(page, dojo):
    rows = []
    pat = re.compile(r'<a[^>]+href="/%s/[^"]*"[^>]*>(.*?)</a>' % re.escape(dojo), re.S)
    for m in pat.finditer(page):
        block = m.group(1)
        title = re.search(r"<h4[^>]*>(.*?)</h4>", block, re.S)
        nums = re.search(r"(\d+)\s*/\s*(\d+)", block)
        if not (title and nums):
            continue
        rows.append({
            "module": strip_tags(title.group(1)),
            "url": m.group(0)[m.group(0).find("href=\"") + 6:].split('"')[0],
            "solved": int(nums.group(1)),
            "total": int(nums.group(2)),
        })
    return rows


def print_summary(rows):
    rows = [r for r in rows if r["progress"]]
    rows.sort(key=lambda r: float(r["progress"].rstrip("%")), reverse=True)
    print(f"pwn.college 学习进度（{len(rows)} 个 dojo 有进度）\n")
    width = max((len(r["dojo"]) for r in rows), default=4) + 2
    for r in rows:
        print(f"  {r['dojo']:<{width}}{r['progress']:>6}   {r['stats']}")


def print_detail(dojo, rows):
    solved = sum(r["solved"] for r in rows)
    total = sum(r["total"] for r in rows)
    pct = solved / total * 100 if total else 0.0
    print(f"dojo: {dojo}  已解 {solved}/{total} ({pct:.1f}%)\n")
    width = max((len(r["module"]) for r in rows), default=6) + 2
    for r in rows:
        mark = " DONE" if r["total"] and r["solved"] == r["total"] else ""
        print(f"  {r['module']:<{width}}{r['solved']:>4}/{r['total']:<4}{mark}")


def parse_challenges(page):
    rows = []
    for m in re.finditer(r'<h4[^>]*class="[^"]*challenge-name[^"]*"[^>]*>(.*?)</h4>', page, re.S):
        block = m.group(0)
        cid = re.search(r'data-challenge-id="([^"]*)"', block)
        if not cid:
            continue
        name = re.search(r'data-challenge-name="([^"]*)"', block)
        rows.append({
            "id": cid.group(1),
            "name": html.unescape(name.group(1)) if name else cid.group(1),
            "solved": "challenge-solved" in block,
        })
    return rows


def require_page(page, what):
    if "<h1>404</h1>" in page:
        sys.exit(f"404: {what} 不存在 (注意 module/challenge 用的是 slug, 可先用 "
                 f"'python pwn_progress.py modules <dojo>' 查看正确 slug)")


def print_challenges(dojo, module, rows):
    done = sum(r["solved"] for r in rows)
    print(f"{dojo}/{module}  ({done}/{len(rows)} 已解)\n")
    for r in rows:
        mark = "[x]" if r["solved"] else "[ ]"
        print(f"  {mark} {r['id']:<32} {r['name']}")


def cmd_next(opener, dojo):
    """按官方顺序找第一个未解试题"""
    _, page = fetch(opener, f"{BASE}/dojo/{dojo}")
    require_page(page, f"dojo '{dojo}'")
    modules = parse_modules(page, dojo)
    if not modules:
        sys.exit(f"未解析到模块: dojo '{dojo}'")
    for mod in modules:
        if mod["total"] and mod["solved"] >= mod["total"]:
            continue  # 已完成
        _, mpage = fetch(opener, BASE + mod["url"])
        chals = parse_challenges(mpage)
        unsolved = next((c for c in chals if not c["solved"]), None)
        if unsolved:
            print(f"dojo:   {dojo}")
            print(f"module: {mod['url'].rstrip('/').rsplit('/', 1)[-1]}")
            print(f"next:   {unsolved['id']}  ({unsolved['name']})")
            print(f"\n启动: python pwn_progress.py start {dojo} "
                  f"{mod['url'].rstrip('/').rsplit('/', 1)[-1]} {unsolved['id']}")
            return
    print(f"dojo '{dojo}' 全部完成 🎉")


def cmd_ssh(args):
    cfg = load_config()
    key = os.path.expanduser(cfg.get("ssh_key", "~/.ssh/pwn.college.key"))
    if not os.path.exists(key):
        sys.exit(f"SSH 私钥不存在: {key}\n"
                 "先在 pwn.college Settings -> SSH Key 添加对应公钥, "
                 "或在 config.json 里用 ssh_key 字段指定私钥路径")
    host = f"{cfg.get('ssh_user', 'hacker')}@{cfg.get('ssh_host', 'dojo.pwn.college')}"
    cmd = ["ssh", "-i", key, "-o", "StrictHostKeyChecking=accept-new", host] + list(args)
    code = subprocess.call(cmd)
    sys.exit(code)


def main():
    args = sys.argv[1:]
    if args and args[0] == "setup":
        cmd_setup()
        return
    if args and args[0] == "ssh":
        cmd_ssh(args[1:])
        return
    dojo = args[0] if args else ""
    cfg = load_config()
    opener, jar = make_opener(cfg)
    if not logged_in(opener):
        login(opener, jar, load_credentials(cfg))
    if dojo in ("modules", "challenges", "next", "start", "solve"):
        if dojo == "modules":
            _, page = fetch(opener, f"{BASE}/dojo/{args[1]}")
            require_page(page, f"dojo '{args[1]}'")
            rows = parse_modules(page, args[1])
            for r in rows:
                mark = " DONE" if r["total"] and r["solved"] == r["total"] else ""
                print(f"  {r['module']:<36}{r['solved']:>4}/{r['total']:<4}{mark}  {r['url']}")
        elif dojo == "challenges":
            _, page = fetch(opener, f"{BASE}/{args[1]}/{args[2]}/")
            require_page(page, f"module '{args[1]}/{args[2]}'")
            print_challenges(args[1], args[2], parse_challenges(page))
        elif dojo == "next":
            cmd_next(opener, args[1])
        elif dojo == "start":
            result = api_post(opener, "/pwncollege_api/v1/docker",
                              {"dojo": args[1], "module": args[2], "challenge": args[3]})
            if result.get("success"):
                print(f"已启动 {args[1]}/{args[2]}/{args[3]}\n"
                      f"进入: python pwn_progress.py ssh  (远程执行: ssh 后直接跟命令)")
            else:
                sys.exit(f"启动失败: {result.get('error', result)}")
        elif dojo == "solve":
            if len(args) < 5:
                sys.exit("用法: python pwn_progress.py solve <dojo> <module> <challenge> <flag>")
            result = api_post(opener, f"/pwncollege_api/v1/dojos/{args[1]}/{args[2]}/{args[3]}/solve",
                              {"submission": args[4]}, timeout=30)
            status = result.get("status", "error")
            msg = {"correct": "✅ 正确, 已记录!",
                   "already_solved": "该试题此前已解决",
                   "incorrect": "❌ 错误的 flag"}.get(status, result.get("error", result))
            print(f"{args[1]}/{args[2]}/{args[3]}: {msg}")
        return
    if dojo:
        _, page = fetch(opener, f"{BASE}/dojo/{dojo}")
        rows = parse_modules(page, dojo)
        if not rows:
            sys.exit(f"未解析到模块: dojo '{dojo}' 不存在或页面结构已变化")
        print_detail(dojo, rows)
    else:
        _, page = fetch(opener, BASE + "/dojos")
        print_summary(parse_dojos(page))


if __name__ == "__main__":
    main()
