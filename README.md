# Realm Pro Suite v34（优化版）

面向 **转发吞吐 / 低延迟 / 稳定可靠** 的一套“面板 + Agent”管理套件，用来集中管理多台机器上的 **realm** 转发规则。

- **Panel（面板）**：集中管理节点（Agent），可视化编辑规则、备份/恢复、连接图、负载均衡展示。
- **Agent（被控机）**：部署在每台需要转发的机器上，提供 API（保存/应用规则、探测连通、上报状态），并将规则落地到 `/etc/realm/config.json` 后重启 `realm.service`。

本优化版的目标场景：**TCP 为主、少量 UDP、包含 ws/wss**（有隧道/伪装需求），同时尽可能提升吞吐、降低抖动，并保证大规模规则/节点下依然稳定。

---

## 目录

- [1. 组件与工作方式](#1-组件与工作方式)
- [2. 环境与端口](#2-环境与端口)
- [3. 一键安装流程（推荐）](#3-一键安装流程推荐)
  - [3.1 安装 Panel](#31-安装-panel)
  - [3.2 在 Panel 添加节点并“一键接入”](#32-在-panel-添加节点并一键接入)
  - [3.3 验证节点在线与服务状态](#33-验证节点在线与服务状态)
- [4. 创建与维护转发规则（面板操作）](#4-创建与维护转发规则面板操作)
  - [4.1 普通 TCP/UDP 转发](#41-普通-tcpudp-转发)
  - [4.2 多目标负载均衡（Round-robin / IP-hash / 权重）](#42-多目标负载均衡round-robin--ip-hash--权重)
  - [4.3 WSS 隧道（发送机/接收机自动同步）](#43-wss-隧道发送机接收机自动同步)
  - [4.4 应用配置（真正让 realm 生效）](#44-应用配置真正让-realm-生效)
- [5. 性能/稳定性优化说明（本版本新增）](#5-性能稳定性优化说明本版本新增)
  - [5.1 systemd：提升并发上限（nofile/tasks）](#51-systemd提升并发上限nofiletasks)
  - [5.2 sysctl：网络栈稳态参数](#52-sysctl网络栈稳态参数)
  - [5.3 pool 级 network：给所有旧规则“一键加优化参数”](#53-pool-级-network给所有旧规则一键加优化参数)
  - [5.4 TCP 主、少量 UDP、含 ws/wss 的推荐策略](#54-tcp-主少量-udp含-wswss-的推荐策略)
- [6. 备份 / 恢复 / 迁移 / 升级](#6-备份--恢复--迁移--升级)
- [7. 常用运维命令](#7-常用运维命令)
- [8. 常见问题排查](#8-常见问题排查)

---

## 1) 组件与工作方式

整体链路（简化示意）：

```
浏览器
  │
  │  http://<panel_ip>:6080
  ▼
Panel（/opt/realm-panel）
  │ ① 保存规则（desired pool）
  │ ② 节点上报 / 下发命令（push-report）
  ▼
Agent（/opt/realm-agent）
  │ ③ 写入 /etc/realm/pool_full.json
  │ ④ 生成 /etc/realm/config.json
  │ ⑤ systemctl restart realm.service
  ▼
realm（/usr/local/bin/realm）
```

**关键点：**
- Panel 与 Agent 通信优先走 **“Agent 主动上报（push-report）”**：只要 Agent 能访问 Panel 的 `http(s)://panel/api/agent/report`，即使 Panel 不能直连 Agent，也能同步规则并显示状态。
- Agent 会把面板规则保存到：
  - `/etc/realm/pool_full.json`（完整规则，包含 disabled 等）
  - `/etc/realm/pool.json`（运行规则：自动过滤 disabled）
  - `/etc/realm/config.json`（给 realm 的最终配置）

---

## 2) 环境与端口

### 2.1 支持系统
安装脚本使用 `apt-get`，推荐：
- Debian 10/11/12
- Ubuntu 20.04/22.04/24.04

需 root 权限（脚本会写 systemd、/etc、/opt 等目录）。

### 2.2 默认端口
- **Panel**：`6080/tcp`（可安装时自定义）
- **Agent**：`18700/tcp`（可安装时自定义）
- **realm**：由你的规则决定（listen 端口）

### 2.3 目录与文件
- Panel 程序目录：`/opt/realm-panel/panel`
- Panel 数据库：`/etc/realm-panel/panel.db`
- Panel 登录信息：`/etc/realm-panel/credentials.json`
- Agent 程序目录：`/opt/realm-agent/agent`
- Agent API Key：`/etc/realm-agent/api.key`
- 节点规则池：`/etc/realm/pool_full.json`
- realm 配置：`/etc/realm/config.json`

---

## 3) 一键安装流程（推荐）

### 3.1 安装 Panel

在“面板机”执行（root）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cyeinfpro/Realm/main/realm_panel.sh)
```

根据提示输入：
- 面板登录用户名（默认 `admin`）
- 面板登录密码（必填）
- 面板端口（默认 `6080`）

安装完成后，浏览器打开：

```
http://<你的面板IP>:6080
```

> 离线安装：把仓库 ZIP 放到面板机，然后运行脚本选择“离线模式”，输入 ZIP 路径即可。

### 3.2 在 Panel 添加节点并“一键接入”

1）登录 Panel 后，点击「添加机器 / 接入」
- 填“节点 IP/域名”（默认不需要写端口；如 Agent 非 18700 可写 `ip:port`）
- 保存后会进入该节点详情页

2）在节点详情页里复制「接入命令」，到目标机器执行（root）：

```bash
curl -fsSL http://<panel_ip>:6080/join/<token> | bash
```

这条命令会自动完成：
- 写入节点专属 API Key：`/etc/realm-agent/api.key`
- 安装/更新 Agent（从面板的 `/static/realm-agent.zip` 拉取离线包，避免 GitHub 不通）
- 安装 realm 二进制（优先从面板缓存下载）
- 安装 `realm.service`（并做性能相关的 systemd 配置）
- 写入 Agent 上报配置 `/etc/realm-agent/panel.env`，让 Agent 开始主动上报

### 3.3 验证节点在线与服务状态

在节点机执行：

```bash
systemctl status realm-agent --no-pager
systemctl status realm --no-pager
```

在面板节点列表里：
- “上报时间”持续更新 = 节点在线
- 规则页能看到“连通/流量/活跃连接” = Agent 数据正常

---

## 4) 创建与维护转发规则（面板操作）

进入某节点后，点击「+ 创建转发」或「+ 新增规则」。

> 规则保存后只是写进“规则池”，**需要点一次「应用配置」** 才会让 realm 立即生效。

### 4.1 普通 TCP/UDP 转发

适合：端口转发、四层代理。

表单字段说明（常用）：
- **Listen**：本地监听，例如 `0.0.0.0:443`
- **目标（Remotes）**：一行一个目标，例如：
  ```
  1.2.3.4:443
  5.6.7.8:443
  ```
- **协议（Protocol）**：
  - `tcp`：只转发 TCP（推荐用于“TCP 为主”的绝大多数规则）
  - `udp`：只转发 UDP
  - `tcp+udp`：同时支持 TCP + UDP（仅在确实需要 UDP 时再用）
- **暂停**：可随时暂停某条规则（不会删除）

### 4.2 多目标负载均衡（Round-robin / IP-hash / 权重）

当你填了多个 remotes：
- 可选 **round-robin**（轮询）或 **ip-hash**（同一来源 IP 尽量落同一目标）
- round-robin 可填写权重：例如 `2,1,1`（对应 remote1/2/3）

适用：多后端、多出口分流、容灾。

### 4.3 WSS 隧道（发送机/接收机自动同步）

适合：需要 ws/wss 外层伪装 / 隧道传输。

本面板的 WSS 隧道采用“**选择接收机自动同步**”模式：
- **发送机（Sender）**：你在这里配置 listen + remotes，并选择一个“接收机节点”。
- **接收机（Receiver）**：面板会自动在接收机创建对应规则（并锁定），你无需手工配置。

操作流程：
1. 在发送机节点，创建规则时把“类型”切到 **WSS**
2. 选择 **接收机节点**（下拉选择）
3. 填写接收机端口（可选；为空则自动选择）
4. 填写 WSS 参数：
   - **Host**：伪装域名（例如 `cdn.jsdelivr.net`）
   - **Path**：伪装路径（例如 `/ws/xxxxx`）
   - **SNI**：一般等于 Host
   - **TLS**：通常开启
   - **Insecure**：如证书校验有问题可勾选（会降低安全性）

保存后：
- 发送机规则会保留“原始目标 remotes”
- 接收机会自动生成“对等规则”，并显示为锁定/不可手动编辑（避免两端不一致）
- 以后修改/暂停/删除，请都在“发送机节点”操作，面板会自动同步两端

### 4.4 应用配置（真正让 realm 生效）

在节点规则页点击「应用配置」会触发：
- Agent 把 pool_full.json → 生成 `/etc/realm/config.json`
- `systemctl restart realm.service`

你也可以在节点机手动触发（需要 API Key）：

```bash
curl -sS -H "X-API-Key: $(cat /etc/realm-agent/api.key)" \
  http://127.0.0.1:18700/api/v1/apply
echo
```

---

## 5) 性能/稳定性优化说明（本版本新增）

### 5.1 systemd：提升并发上限（nofile/tasks）

安装 Agent 时会：
- 创建/保留 `/etc/systemd/system/realm.service`
- 写入 drop-in：`/etc/systemd/system/realm.service.d/override.conf`
  - `LimitNOFILE=1048576`
  - `TasksMax=infinity`
- 同时 `ExecStart` 默认带 `-n 1048576`（realm 自身 nofile 设置）

> 如果你之前已经手工改过 realm.service，本版本不会强行覆盖你的 ExecStart，只会补充 drop-in 限制。

### 5.2 sysctl：网络栈稳态参数

安装 Agent 时若发现不存在 `/etc/sysctl.d/99-realm.conf`，会写入一份“稳态网络调优”并 `sysctl --system`（best-effort）：
- backlog / buffer 提升（高并发更稳）
- keepalive 参数（配合 realm 侧 keepalive 更好回收半死连接）
- fq + bbr（旧内核不支持会忽略，不影响安装）

你可以查看内容：

```bash
cat /etc/sysctl.d/99-realm.conf
```

### 5.3 pool 级 network：给所有旧规则“一键加优化参数”

**重点：**这版支持在规则池顶层增加 `network`，作为全局默认值；每条 endpoint 仍可用自身 `network` 覆盖。

你可以通过“备份 → 编辑 JSON → 恢复”来设置：

1）在面板节点页点「更多 → 备份规则（下载）」
2）打开下载的 JSON，加入/修改顶层 `network`（示例）：

```json
{
  "network": {
    "tcp_timeout": 8,
    "udp_timeout": 60,
    "tcp_keepalive": 15,
    "tcp_keepalive_probe": 3
  },
  "endpoints": [
    {"listen":"0.0.0.0:443","remotes":["1.2.3.4:443"],"protocol":"tcp+udp"}
  ]
}
```

3）回到面板节点页点「更多 → 恢复规则（粘贴）」把 JSON 粘进去恢复
4）最后点一次「应用配置」

> 说明：`tcp_timeout/udp_timeout/tcp_keepalive/...` 的具体可用字段取决于你安装的 realm 版本；不识别的字段通常会被 realm 忽略或报错。若应用后 realm 启动失败，请在节点机 `journalctl -u realm -e` 查看错误并调整字段。

### 5.4 TCP 主、少量 UDP、含 ws/wss 的推荐策略

为了“吞吐 + 低延迟 + 稳定”：

1）**默认规则尽量用 `tcp`**
- 只有确实需要 UDP（例如游戏/语音/特定协议）才用 `udp` 或 `tcp+udp`

2）**WSS 只用在必须的链路**
- ws/wss 会引入额外封装与 TLS 开销，吞吐与延迟波动都会更明显
- 业务链路能不用 wss 就别用

3）全局 network 推荐起步值（可按你的网络环境调整）：
- `tcp_timeout: 8`（连接建立卡死的保护）
- `tcp_keepalive: 15` + `tcp_keepalive_probe: 3`（更快清理半死连接，降低抖动）
- `udp_timeout: 60`（UDP 映射不要太大，避免资源长期占用）

4）大规模规则/高并发时，优先排查：
- FD 是否够：`ulimit -n` / `systemctl show realm.service -p LimitNOFILE`
- 软中断是否过高：`top` 看 `%si`
- 内核队列是否打满：`ss -s` / `nstat`

---

## 6) 备份 / 恢复 / 迁移 / 升级

### 6.1 备份规则
面板节点页：「更多 → 备份规则（下载）」

节点机也可手动备份：

```bash
cp /etc/realm/pool_full.json /root/pool_full.json.bak.$(date +%s)
```

### 6.2 恢复规则
面板节点页：「更多 → 恢复规则（粘贴）」

恢复后记得点「应用配置」。

### 6.3 升级到本优化版后，旧规则会不会自动修改？
- **如果你一直用面板/Agent 管理规则：**
  - 旧规则在 `pool_full.json` / 面板 DB 里，升级不会丢。
  - Agent 会用新的生成逻辑重新生成 `config.json`，旧规则会“自动按新逻辑落地”。
- **如果你以前手工改 `/etc/realm/config.json`：**
  - 一旦你在面板点“应用配置”，`config.json` 会被覆盖。
  - 建议先把手工规则整理成面板规则（或写入 pool_full/备份恢复）。

### 6.4 更新面板 / 更新 Agent
- 更新 Panel：在面板机重新运行 `realm_panel.sh` 选择“更新面板”。
- 更新 Agent：最稳的方法是在面板节点页复制「接入命令」再跑一次（会强制更新 Agent）。

---

## 7) 常用运维命令

### 面板机
```bash
systemctl status realm-panel --no-pager
journalctl -u realm-panel -f

# 面板 DB
ls -l /etc/realm-panel/panel.db
```

### 节点机
```bash
systemctl status realm-agent --no-pager
journalctl -u realm-agent -f

systemctl status realm --no-pager
journalctl -u realm -e

# 查看最终 realm 配置
cat /etc/realm/config.json | head

# 手动应用（需要 API key）
curl -sS -H "X-API-Key: $(cat /etc/realm-agent/api.key)" http://127.0.0.1:18700/api/v1/apply && echo
```

---

## 8) 常见问题排查

### 8.1 节点显示离线
- 节点机是否能访问面板：`curl -I http://<panel_ip>:6080/`
- 节点机 `systemctl status realm-agent` 是否 active
- `cat /etc/realm-agent/panel.env` 是否存在且包含 `REALM_PANEL_URL/REALM_AGENT_ID`

### 8.2 点了“应用配置”但不生效
- 看 `realm` 是否重启成功：`systemctl status realm`
- 看日志：`journalctl -u realm -e`
- 检查 `/etc/realm/config.json` 是否生成：
  ```bash
  test -s /etc/realm/config.json && echo OK
  ```

### 8.3 应用后 realm 启动失败
- 多半是 `config.json` 某字段不被当前 realm 支持或格式错误
- 在节点机查看错误：`journalctl -u realm -e`
- 回滚方式：用备份恢复旧 pool，再点应用

### 8.4 WSS 隧道不通
- 确认发送机与接收机都在线
- Host/Path/SNI 是否一致、是否为空
- TLS/Insecure 勾选是否符合你的证书与环境
- 先用纯 TCP 规则验证链路，排除基础网络问题

---

### License / 免责声明
本套件仅提供规则管理与部署便利，实际使用请遵守当地法律法规与服务商条款。对因错误配置造成的中断/损失需自行承担。
