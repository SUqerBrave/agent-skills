# agent-skills

个人 AI agent 技能库（SKILL.md 格式），跨 ZCode / Claude Code / OpenClaw 等使用 `.agents/skills` 约定的 agent 通用。

## 结构

```
skills/
├── pwn-progress/             # pwn.college 学习进度查询（纯 Python，DPAPI/钥匙串加密凭据）
├── ncm-cli-setup/            # 网易云音乐 CLI 安装配置
├── netease-music-assistant/  # 网易云音乐智能助手（推荐/播放控制）
├── netease-music-cli/        # 网易云音乐 CLI 操作
├── find-skills/              # 技能发现
└── opencli-*/                # OpenCLI 内置技能同步副本（来自 @jackwener/opencli npm 包）
```

## 接入

克隆后把需要的 skill 链接进 agent 的技能目录（本体在本仓库，目录里放链接）：

**Windows（junction，无需管理员）：**

```bat
git clone https://github.com/SUqerBrave/agent-skills.git %USERPROFILE%\code\agent-skills
cmd /c mklink /j "%USERPROFILE%\.agents\skills\pwn-progress" "%USERPROFILE%\code\agent-skills\skills\pwn-progress"
```

**Linux / macOS：**

```sh
git clone https://github.com/SUqerBrave/agent-skills.git ~/code/agent-skills
ln -s ~/code/agent-skills/skills/pwn-progress ~/.agents/skills/pwn-progress
```

ZCode 用户再从 `.agents\skills` 向 `.zcode\skills` 建 junction 即可复用同一份本体。

## 约定

- **凭据永不入库**：所有凭据存于 `~/.config/<skill>/`（如 pwn-progress 的 DPAPI 加密 `credentials.bin`），skill 目录内只放 `*.example.json` 模板；`.gitignore` 兜底。
- 自研 skill 保持单文件脚本 + 仅标准库优先，便于离线使用。
- opencli-* 技能随上游版本更新：升级 npm 包后从
  `$(npm root -g)/@jackwener/opencli/skills/` 重新拷贝覆盖。

## 更新 opencli 内置技能

```sh
npm install -g @jackwener/opencli@latest
SRC=$(npm root -g)/@jackwener/opencli/skills
for s in $(ls "$SRC"); do rm -rf skills/$s && cp -r "$SRC/$s" skills/$s; done
```
