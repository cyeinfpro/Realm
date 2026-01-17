# Realm Pro Suite (Stable Build)

此版本已修复你遇到的两个关键问题：

- ✅ **安装时会要求设置面板用户名/密码**（你想要的行为）
- ✅ **配对码只用于 WSS 参数同步**（用于自动回填 Host/Path/SNI/Insecure，不再用于“链接机器/绑定节点”）
- ✅ **安装脚本不再依赖固定目录名（v15/v16）**：会自动识别 `panel/`、`agent/` 或 `realm-pro-suite-vXX/panel`、`realm-pro-suite-vXX/agent`

---

## 目录结构（建议）

把下面这些放在仓库根目录：

```
Realm/
  realm_panel.sh
  realm_agent.sh
  panel/
  agent/
```

> 如果你保留版本目录（例如 `realm-pro-suite-v16/panel`），安装脚本也能自动识别。

---

## 组件说明

- **Agent**：运行在每台节点上，提供本地 API（Bearer Token 鉴权）。
- **Panel**：统一 Web 管理面板，可管理多个 Agent。

---

## 快速安装

### 1) 安装 Agent

```bash
bash realm_agent.sh
```

脚本会输出：

- Agent API 地址
- Agent Token（添加节点时需要）

---

### 2) 安装 Panel

```bash
bash realm_panel.sh
```

安装过程中会要求你输入：

- 面板端口（默认 18750）
- 面板用户名（默认 admin）
- 面板密码（必填）

安装完成会提示面板访问地址。

---

## WSS 对接码如何用（重点）

### ✅ 你要的逻辑：对接码 = 自动获取 WSS 服务端参数

1) 在 **WSS 服务端（Server）** 创建规则
- 创建成功后，面板会返回一个 **对接码（6位数字）**

2) 在 **WSS 客户端（Client）** 创建规则
- 填入这个 **对接码**
- 面板会自动回填：
  - Host
  - Path
  - SNI
  - Insecure

> 对接码只用于 **参数同步**，与“绑定节点/链接机器”无关。
