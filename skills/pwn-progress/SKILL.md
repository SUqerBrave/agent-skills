---
name: pwn-progress
description: 查询用户在 pwn.college 的学习进度。当用户提到 pwn.college、dojo 进度、学习进度、刷题进度、解题情况、CTF 学习时使用。纯 Python 实现，凭据 DPAPI/钥匙串加密存储，支持自动登录，无需浏览器在线。
allowed-tools: Bash(python:*), Read
---

# pwn.college 学习进度查询（纯 Python）

单文件脚本 `pwn_progress.py`（与本 SKILL.md 同目录，仅用标准库）。原理：进度由服务端渲染在 HTML 里（无进度 API），脚本用 urllib 带登录 cookie 抓 `/dojos` 和 `/dojo/<id>` 页面并解析。

## 用法

```sh
python pwn_progress.py setup          # 首次: 交互式录入凭据 (密码不回显)
python pwn_progress.py                # 所有有进度的 dojo 总览（按百分比排序）
python pwn_progress.py computing-101  # 单个 dojo 的模块明细
```

## 凭据存储（跨平台，绝不进 SKILL.md / 模型上下文）

配置目录 `~/.config/pwn-progress/`（可用 `PWNC_CONF_DIR` 覆盖），存储后端按平台自动选择：

| 平台 | 后端 | 依赖 |
|---|---|---|
| Windows | DPAPI 加密 `credentials.bin`（绑定当前用户，拷走无法解密） | 无（ctypes 调 crypt32） |
| Linux/macOS 桌面 | 系统钥匙串（GNOME Keyring/KWallet/Keychain） | `pip install keyring` |
| 无钥匙串 headless | 0600 权限明文文件（setup 时会警告），或环境变量 | 无 |

环境变量 `PWNC_USER` / `PWNC_PASS` 优先级最高（适合 cron/CI）。登录态 cookie 缓存于 `cookies.txt`（POSIX 下自动 chmod 600），失效自动重登。

安全约定：凭据永远只经用户手输给脚本，agent 不索要、不回显、不写入任何文件；SKILL.md 与对话中不得出现明文凭据。

## 登录与网络

- 登录态探测：`users/me` API 返回 JSON 才算已登录；未登录自动走 `/login` 表单（GET 取 CSRF nonce → POST 凭据）。
- `user_agent` 用用户浏览器的真实 UA 避免 Cloudflare 拦截；配置缺省时尝试 `opencli browser eval navigator.userAgent` 取一次并缓存，无浏览器则用兜底值。被 403 时提示更新 UA。

## 判读

- 总览只显示有进度的 dojo（progress 为 null 表示从未做过）。
- 模块明细里 `solved == total` 标记 DONE；可结合总览推荐下一步（官方顺序 Getting Started → Core Material）。
- dojo id 从总览 url 字段取（`/dojo/<id>`）。

## 手动后备（浏览器在线时）

```sh
opencli browser open "https://pwn.college/dojos" --session pwnc
opencli browser eval "(() => [...document.querySelectorAll('main a[href^=\"/dojo/\"]')].map(a => { const h = a.querySelector('h4'); if (!h) return null; const pct = [...a.querySelectorAll('span')].map(s => s.textContent.trim()).find(t => t.endsWith('%')); return { dojo: h.textContent.trim(), progress: pct || null }; }).filter(Boolean))()" --session pwnc
```

模块明细同理：打开 `/dojo/<id>` 后取每个 `main ul a` 内 `h4` 与 `(\d+)\s*/\s*(\d+)`。
