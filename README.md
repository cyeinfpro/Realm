# Realm Pro Suite v31

这个包包含两部分：

- **Realm Pro Panel（面板）**：集中管理多台机器（Agent），提供规则列表 / 编辑 / 连接图可视化 / 负载均衡可视化。
- **Realm Agent（被控机）**：部署在每台需要被管理的机器上，提供 API 来读写规则并应用到 `/etc/realm/config.json`。

> 说明：v31 彻底移除了 `bcrypt/passlib` 依赖，面板密码使用 PBKDF2-SHA256 存储，不会再出现 bcrypt 版本/72字节限制报错。

---

## 1) 安装 Agent（每台被控机都装一次）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cyeinfpro/Realm/main/realm_agent.sh)
```

如果希望 Agent 在安装 realm 时优先从面板机拉取文件（面板会在更新时刷新这些文件），请设置面板地址：

```bash
REALM_PANEL_URL="http://<面板IP>:6080" bash <(curl -fsSL https://raw.githubusercontent.com/cyeinfpro/Realm/main/realm_agent.sh)
```

安装完成后会输出：

- Agent API 地址（默认端口 `18700`）
- **API Key**（复制到面板里添加机器）

---

## 2) 安装 Panel（控制台机器装一次）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cyeinfpro/Realm/main/realm_panel.sh)
```

然后用浏览器打开：

- `http://<你的IP>:6080`

---

## 3) 面板功能

- 机器列表（添加/删除）
- 规则列表（启用/禁用）
- 规则编辑（listen/remote/wss/balance/权重）
- 连接图（Graph）
- 负载均衡可视化（Load Balancer）

---

## 目录结构

```
Realm/
  realm_panel.sh
  realm_agent.sh
  panel/
  agent/
```
