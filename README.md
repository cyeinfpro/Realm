# Nexus Network Control Plane

面向多节点网络转发与网站运维的一体化控制平面，包含：
- `Panel`：集中编排、监控、备份与可视化管理
- `Agent`：节点侧执行器，负责规则落地、状态上报与站点操作

> 当前仓库代码对应：`Panel v34`（`panel/app/core/settings.py`）与 `Agent v43`（`agent/app/main.py`）。

---

## 1. Nexus 是什么

Nexus 用来统一管理多台机器上的转发规则与站点运维能力，重点解决：
- 多节点转发规则配置分散、发布不一致
- WSS / 内网穿透双端规则易错、难同步
- 规则健康、流量、连接、系统指标缺少统一视图
- 网站部署、证书、文件管理、分享链路碎片化

Nexus 的核心模式是 **Agent 主动上报（push-report）**：
- Panel 不必持续直连 Agent 才能感知状态
- 面板侧保存 desired 配置，Agent 拉取并执行
- 适合 NAT、内网、弱连通场景

---

## 2. 架构与数据流

```text
Browser
  -> Panel (FastAPI + SQLite)
      1) 保存 desired pool / 网站配置 / 监控配置
      2) 展示实时状态、历史曲线、拓扑与运维页面
      3) 在 Agent 上报时下发签名命令（sync_pool/pool_patch/update/reset）
  <- Agent (FastAPI)
      4) 周期上报 report/stats/sys（gzip）
      5) 执行命令并 ACK 版本
      6) 将规则写入 /etc/realm/pool_full.json -> 生成 /etc/realm/config.json -> 重启 realm
```

关键设计：
- **版本对齐**：`desired_pool_version` / `agent_ack_version` 防止错配
- **命令签名**：关键命令使用 HMAC + ts + nonce，防重放
- **回退路径**：Panel 直连 Agent 失败时，尽量改为排队等待 Agent 上报执行

---

## 3. 全功能总览

### 3.1 控制台与节点管理
- 节点接入、编辑、删除
- 分组管理与分组排序
- 在线/离线状态、心跳时间、Agent 版本展示
- 一键接入命令与一键卸载命令
- 节点角色：普通节点 / 网站机节点；可标记内网节点
- 一键更新全部 Agent（强制重装流程）
- 全量备份 / 全量恢复（异步进度）
- 全局一键重置规则流量统计

### 3.2 转发规则编排（节点页）
- 规则类型：
  - 普通转发（TCP/UDP/TCP+UDP）
  - WSS 隧道（发送机/接收机自动同步）
  - 内网穿透（公网入口/内网出口自动同步）
- 规则操作：新增、编辑、删除、批量启停、批量删除、收藏、搜索、筛选
- 规则保护：同步生成的接收侧规则默认锁定，避免误改
- 负载策略：RoundRobin / IPHash + 权重
- 自适应负载均衡（基于可用性/延迟/错误率自动调权）
- QoS（端口防护）：
  - 带宽上限
  - 最大并发连接
  - 每秒新建连接速率
- 高级网络参数：
  - `through` / `interface` / `listen_interface`
  - `network` 覆盖（tcp_timeout、udp_timeout、keepalive 等）
  - PROXY protocol / MPTCP / listen_transport / remote_transport
- WSS 高级参数：host/path/sni/tls/insecure、接收端端口自动避让
- 内网穿透高级参数：
  - 隧道端口 / 公网入口地址
  - ACL（allow/deny source、时间窗、token）

### 3.3 规则发布与校验
- 保存时校验：
  - 静态结构校验（listen/remote/权重/端口冲突等）
  - 运行时预检（Agent `/api/v1/netprobe` rules 模式）
- 同步策略：
  - 全量 `sync_pool`
  - 单规则增量 `pool_patch`（条件满足时）
- 发布方式：
  - 同步接口
  - 异步任务（可轮询状态、失败重试）

### 3.4 观测与历史
- 规则级实时指标：
  - 流量（上/下行）
  - 活跃连接 / 总连接
  - 目标健康探测
- 节点系统指标：CPU / 内存 / 磁盘 / 网络速率 / uptime
- 历史曲线（持久化到 Panel DB）：
  - 流量速率与连接历史
  - 支持按规则/汇总窗口查看
  - 支持清空历史

### 3.5 网络波动监控（NetMon）
- 多监控项，支持 `ping` / `tcping`
- 单监控支持多节点并行探测
- 阈值：Warn/Crit
- 时间窗口 + 分层聚合（rollup）
- 只读分享页 / 大屏墙（签名 Token + TTL）
- 支持分享固定时间段或跟随窗口

### 3.6 网站管理（Website Ops）
- 站点类型：`static` / `php` / `reverse_proxy`（当前 Web Server 为 nginx）
- 站点生命周期：创建、编辑、删除
- 节点环境一键确保/卸载：nginx、php-fpm、acme.sh
- SSL 证书：申请/续期（HTTP-01，自动回写 nginx）
- HTTPS 强制跳转开关
- 健康检查与诊断：
  - 后台周期健康巡检
  - 站点诊断页（live + 历史事件 + 检查记录）
- 文件管理：
  - 列表、读取、编辑、保存、删除、解压
  - 分片上传、文件夹上传、上传状态查询
  - 文件/目录下载（目录流式打包 ZIP）
- 文件分享：
  - 短链分享、过期控制、撤销
  - 单文件直链下载 / 多文件打包下载
  - 大包异步打包任务与进度查询

### 3.7 备份与恢复
- 单节点规则备份/恢复
- 全量备份（ZIP）：
  - 节点
  - 规则
  - 站点配置
  - 站点文件
  - 证书元数据
  - NetMon 监控配置
- 全量恢复（异步任务、步骤进度）

---

## 4. 安装与接入

### 4.1 一键安装 Panel（推荐）

```bash
bash <(curl -fsSL https://nexus.infpro.me/nexus/realm_panel.sh || curl -fsSL https://raw.githubusercontent.com/cyeinfpro/NexusControlPlane/main/realm_panel.sh)
```

脚本支持：
- 在线拉取（自动探测仓库 ZIP / manifest）
- 离线 ZIP 安装
- 更新 / 重启 / 卸载

默认安装目录：
- `/opt/realm-panel`
- `/etc/realm-panel`

默认面板端口（脚本安装）：`6080`

### 4.2 节点接入 Agent

在 Panel 创建节点后，进入节点页执行“接入命令”。
该命令会：
- 写入 `/etc/realm-agent/api.key`
- 安装/更新 Agent
- 安装/更新 realm 二进制
- 写入上报配置并启动服务

默认 Agent 端口：`18700`

---

## 5. 关键目录与文件

### 5.1 Panel
- 程序目录：`/opt/realm-panel/panel`
- 数据库：`/etc/realm-panel/panel.db`
- 凭据：`/etc/realm-panel/credentials.json`
- Secret：`/etc/realm-panel/secret.key`
- 环境变量文件：`/etc/realm-panel/panel.env`

### 5.2 Agent
- 程序目录：`/opt/realm-agent/agent`
- API Key：`/etc/realm-agent/api.key`
- 上报配置：`/etc/realm-agent/panel.env`（或 agent.env）
- 规则池（完整）：`/etc/realm/pool_full.json`
- 规则池（运行）：`/etc/realm/pool.json`
- realm 最终配置：`/etc/realm/config.json`
- ACK 版本：`/etc/realm-agent/panel_ack.version`
- 更新状态：`/etc/realm-agent/agent_update.json`

---

## 6. 核心 API 速览

### 6.1 Panel 侧（节选）
- Agent 上报：`POST /api/agent/report`
- 节点规则：
  - `GET /api/nodes/{id}/pool`
  - `POST /api/nodes/{id}/pool`
  - `POST /api/nodes/{id}/pool_async`
  - `POST /api/nodes/{id}/rule_delete_async`
- 节点状态：
  - `GET /api/nodes/{id}/stats`
  - `GET /api/nodes/{id}/sys`
  - `GET /api/nodes/{id}/stats_history`
- 隧道同步：
  - `POST /api/wss_tunnel/save_async`
  - `POST /api/intranet_tunnel/save_async`
- 网络波动：
  - `GET /api/netmon/snapshot`
  - `POST /api/netmon/monitors`
  - `POST /api/netmon/share`
- 网站管理：`/websites/*`（创建、SSL、诊断、文件、分享）
- 全量备份恢复：`/api/backup/full/*`、`/api/restore/full/*`

### 6.2 Agent 侧（节选）
- 基础：
  - `GET /api/v1/info`
  - `GET /api/v1/pool`
  - `POST /api/v1/pool`
  - `POST /api/v1/apply`
  - `GET /api/v1/stats`
  - `GET /api/v1/sys`
  - `POST /api/v1/netprobe`
  - `POST /api/v1/traffic/reset`
- 内网穿透：
  - `GET /api/v1/intranet/cert`
  - `GET /api/v1/intranet/status`
- 网站：
  - `/api/v1/website/env/*`
  - `/api/v1/website/site/*`
  - `/api/v1/website/ssl/*`
  - `/api/v1/website/diagnose`
  - `/api/v1/website/files/*`

---

## 7. 安全机制

- Panel 登录密码：PBKDF2-SHA256（含 salt）
- Panel 会话与分享 Token：同一 `SECRET_KEY` 签名
- Agent API：`X-API-Key` 强校验
- 关键下发命令：HMAC 签名 + 时间窗 + nonce 防重放
- 支持按节点配置 Agent TLS 证书校验（`verify_tls`）
- 同步接收侧规则默认锁定，减少误操作

---

## 8. 常用运维命令

### 8.1 Panel 机器

```bash
systemctl status realm-panel --no-pager
journalctl -u realm-panel -f
```

### 8.2 Agent 节点

```bash
systemctl status realm-agent --no-pager
journalctl -u realm-agent -f

systemctl status realm --no-pager
journalctl -u realm -e
```

### 8.3 本地快速检查

```bash
# 检查 Agent 可读 pool
curl -sS -H "X-API-Key: $(cat /etc/realm-agent/api.key)" \
  http://127.0.0.1:18700/api/v1/pool

# 触发 apply
curl -sS -H "X-API-Key: $(cat /etc/realm-agent/api.key)" \
  http://127.0.0.1:18700/api/v1/apply
```

---

## 9. 本地开发运行（可选）

```bash
# Panel
cd panel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 6080

# Agent
cd agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 18700
```

---

## 10. 兼容与建议

- 推荐系统：Debian / Ubuntu（安装脚本使用 `apt`）
- 建议在生产环境用 systemd 托管服务
- WSS/内网穿透场景建议优先验证基础 TCP 规则再切换高级模式
- 大规模规则建议开启并观察预检、历史曲线与 NetMon，逐步放量

---

## 11. 免责声明

本项目提供网络转发与站点运维编排能力。请在合法合规前提下使用，并自行承担配置与运维风险。
