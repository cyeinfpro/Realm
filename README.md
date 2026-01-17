# Realm Pro Suite v14

这是一套 **可直接丢进 GitHub 的完整代码包**（Panel + Agent），包含：

- ✅ 全新 UI 设计（高级玻璃拟态 + 统一交互）
- ✅ 配对码逻辑重做（防重复 / 可过期 / 一键生成）
- ✅ Panel 统一代理管理 Agent（无需浏览器直接访问 Agent）
- ✅ 规则新增 / 编辑 / 删除 / 暂停 / 应用 / 查看日志
- ✅ 目标健康探测（通/断）+ Realm 连接数统计（入站/出站）
- ✅ WSS 支持：客户端 / 服务端 两种模式（可自签证书）

---

## 你需要替换哪里的仓库地址？

仓库 RAW 地址只出现在 **两个安装脚本**的顶部：

1) `realm_panel.sh`
2) `realm_agent.sh`

找到这行并替换：

```bash
REPO_RAW_BASE="https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main"
```

（你已经给了这个地址，因此本包已替换好。）

---

## Panel 一键安装

```bash
bash realm_panel.sh
```

安装后默认监听：`http://服务器IP:18750`

默认管理员：
- 用户名：admin
- 密码：admin

（可在安装时改，也可编辑 `/etc/realm-panel/panel.env` 后重启）

---

## Agent 一键安装（并配对）

在被控机执行：

```bash
bash realm_agent.sh
```

你会被提示输入：
- Panel 地址（例如 `http://10.0.0.2:18750`）
- 配对码（在 Panel 仪表盘生成）

配对成功后，Panel 就能管理该 Agent。

---

## 目录结构

- `panel/`  Web 面板源代码
- `agent/`  Agent API 源代码
- `realm_panel.sh` 一键安装 Panel
- `realm_agent.sh` 一键安装 Agent

---

## 常用命令

### Panel

```bash
systemctl status realm-panel --no-pager
systemctl restart realm-panel
journalctl -u realm-panel -n 100 --no-pager
```

### Agent

```bash
systemctl status realm-agent --no-pager
systemctl restart realm-agent
journalctl -u realm-agent -n 100 --no-pager
```

