# 聊天室项目 —— 全功能测试指南 v3.2.2

> 最后更新：2026-06-15 | 全量测试通过 ✅

---

## 测试结果记录

**测试日期**: 2026-06-15 | **测试人**: fengyang | **结果**: ✅ 全部通过

| 阶段 | 测试项数 | 结果 |
|------|---------|------|
| 自动化测试（pytest） | 151 | ✅ |
| SSL 证书生成 | 1 | ✅ |
| 服务端启动 | 1 | ✅ |
| 用户注册与登录 | 6 | ✅ |
| 好友系统 | 6 | ✅ |
| 私聊消息 | 4 | ✅ |
| 群组系统 | 4 | ✅ |
| 文件传输 | 3 | ✅ |
| 消息撤回 | 2 | ✅ |
| 管理员功能 | 4 | ✅ |
| 消息历史持久化 | 2 | ✅ |
| 配置文件验证 | 2 | ✅ |
| 文件过期清理 | 1 | ✅ |
| **合计** | **37** | **✅** |

> **设计决策（v3.2.2）**:
> 1. 实时查看用户在线情况功能已废弃——仅管理员可通过管理面板查看用户在线状态，普通用户好友列表中不再显示在线/离线标记。
> 2. 消息送达状态（sent/delivered/回执）不再作为关注重点——后续 Flutter 客户端将参考微信消息风格，仅显示消息内容，不展示送达状态标记。

---

## 目录

1. [前置准备](#1-前置准备)
2. [阶段一：服务端启动](#2-阶段一服务端启动)
3. [阶段二：用户注册与登录](#3-阶段二用户注册与登录)
4. [阶段三：好友系统](#4-阶段三好友系统)
5. [阶段四：私聊消息](#5-阶段四私聊消息)
6. [阶段五：群组系统](#6-阶段五群组系统)
7. [阶段六：文件传输](#7-阶段六文件传输)
8. [阶段七：消息撤回](#8-阶段七消息撤回)
9. [阶段八：管理员功能](#9-阶段八管理员功能)
10. [阶段九：消息历史持久化验证](#10-阶段九消息历史持久化验证)
11. [阶段十：配置文件验证](#11-阶段十配置文件验证)
12. [阶段十一：文件过期清理验证](#12-阶段十一文件过期清理验证)
13. [完整测试清单](#13-完整测试清单)
14. [快速 SQL 验证命令](#14-快速-sql-验证命令)

---

## 1. 前置准备

### 1.1 环境确认

```bash
cd ~/PycharmProjects/chatroom
source .venv/bin/activate
python --version          # 应输出 Python 3.12.x
pip list | grep -E "bcrypt|pytest|pyyaml|cryptography"
# 应有 bcrypt, pytest, pyyaml, cryptography
```

### 1.2 生成 SSL 证书

```bash
python SSL/gen_cert.py
```

**预期输出**:

```
证书: SSL/tsetcn.crt
私钥: SSL/tsetcn.key
PEM:  SSL/tsetcn.pem
```

### 1.3 自动化测试（先跑一遍确认基线）

```bash
.venv/bin/python -m pytest tests/ -v
```

**预期**: `151 passed`，零失败。

---

## 2. 阶段一：服务端启动

打开**终端1**：

```bash
cd ~/PycharmProjects/chatroom
source .venv/bin/activate
python server/server_main.py
```

**预期输出**:

```
数据库路径: /home/fengyang/PycharmProjects/chatroom/users.db
2026-06-15 ... [INFO] 服务器启动，监听 127.0.0.1:8090
```

> 如果看到 "启动时清理了 X 个过期文件请求" 也是正常的（`cleanup_expired_file_requests` 在启动时自动运行）。

---

## 3. 阶段二：用户注册与登录

### 3.1 启动第一个客户端（alice）

打开**终端2**：

```bash
cd ~/PycharmProjects/chatroom
source .venv/bin/activate
python client/gui/gui_main.py
```

弹出 GUI 窗口，标题为"网络通讯客户端"。

### 3.2 测试：注册 alice

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 选择 **注册** | — |
| 2 | 用户名输入 `alice`，密码输入 `alice123`（≥6字符） | — |
| 3 | 点击 **确定** | 弹窗"注册成功"，窗口变为聊天主界面，标题变为"聊天室 - alice" |

### 3.3 测试：客户端预验证——短用户名

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 退出后重新打开客户端 | — |
| 2 | 选择**注册**，用户名输入 `a`（<3字符） | — |
| 3 | 点击 **确定** | 弹窗"输入错误：用户名长度不能少于 3 个字符"，**不会连接服务器** |

### 3.4 测试：客户端预验证——SQL 注入尝试

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 用户名输入 `alice'; DROP TABLE users; --` | — |
| 2 | 点击确定 | 弹窗"输入错误：用户名只能包含字母、数字、下划线和连字符" |

### 3.5 测试：短密码被拒绝

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 用户名输入 `testuser`，密码输入 `12345`（5字符） | — |
| 2 | 点击确定 | 弹窗"输入错误：密码长度不能少于 6 个字符" |

### 3.6 测试：重复注册被拒绝

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 选择**注册**，用户名输入 `alice`，密码 ≥6字符 | — |
| 2 | 点击确定 | 弹窗"错误：用户已存在" |

### 3.7 测试：登录 alice

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 如有"登录"界面，选择**登录**，输入 `alice` / `alice123` | — |
| 2 | 点击确定 | 进入聊天主界面 |

### 3.8 启动第二个客户端（bob）

打开**终端3**，同样启动：

```bash
cd ~/PycharmProjects/chatroom
source .venv/bin/activate
python client/gui/gui_main.py
```

注册 `bob` / `bob12345`（≥6字符），然后登录。

**此时**: 两个客户端并列，双方的好友列表均为空。

---

## 4. 阶段三：好友系统

### 4.1 Alice 添加 Bob 为好友

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **Alice** 客户端：点击 **添加好友** | 弹出输入框 |
| 2 | 输入 `bob`，确认 | Alice 的"服务器"聊天窗口显示"好友请求已发送给 bob" |
| 3 | **Bob** 客户端：服务器窗口显示"收到好友请求: alice" | — |
| 4 | **Bob**：点击 **查看好友请求** | 弹出窗口，显示来自 alice 的请求，有"接受"和"拒绝"按钮 |
| 5 | **Bob**：点击 **接受** | 双方好友列表中出现对方 |

**验证**:

- Alice 好友列表显示 `bob`
- Bob 好友列表显示 `alice`

### 4.2 测试：拒绝好友请求

> 先让 bob 向一个不存在的好友发请求，触发错误处理。

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **Alice**：向不存在的用户 `ghost` 发好友请求 | 弹窗"用户 ghost 不存在"（不崩溃） |
| 2 | 向自己发好友请求（用户名 `alice`） | 弹窗"好友请求发送失败" |

---

## 5. 阶段四：私聊消息

### 5.1 在线私聊

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **Alice**：在好友列表中**单击 bob** | 聊天区域标题变为"与 bob 的聊天" |
| 2 | 输入框输入 `Hello Bob!`，点击 **发送** | Alice 窗口显示"alice: Hello Bob! [sent] (message_id)" |
| 3 | **Bob**：收到消息 | Bob 窗口显示"alice: Hello Bob! [delivered] (message_id)"，注意状态变为 `delivered` |

**验证状态流转**:

- Alice 看到 `[sent]` → 收到回执后状态更新
- Bob 看到 `[delivered]`

### 5.2 消息回执

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | Bob 发送 `Hi Alice!` 回复 | Alice 收到，双方消息状态更新 |

### 5.3 向非好友发消息被阻止

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 注册第三个用户 `charlie`（另开终端4），登录，不添加好友 | — |
| 2 | **Alice**：试图向 charlie 发消息 | 无法操作（charlie 不出现在好友列表中） |

> 也可以通过服务端日志验证：服务端应打印 "消息发送失败: alice -> charlie, 非好友"。

### 5.4 离线消息

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **关闭 Bob 的客户端**（直接关窗口或点退出） | — |
| 2 | **Alice** 发送 `Are you there?` 给 bob | Alice 看到"用户 bob 离线，消息已保存" |
| 3 | **重新启动 Bob 客户端**，用 `bob` / `bob12345` 登录 | — |
| 4 | 观察 Bob 聊天窗口 | 收到 `[历史]alice: Are you there?` 标记为离线消息 |

---

## 6. 阶段五：群组系统

### 6.1 创建群组

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **Alice**：点击 **群组管理** → **创建群组** | 弹出输入框 |
| 2 | 输入群名 `开发小组`，确认 | 服务器窗口显示"群组 开发小组 创建成功，ID: 1" |
| 3 | Alice 好友列表中出现 `群组 1` | — |

### 6.2 加入群组

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **Bob**：点击 **群组管理** → **加入群组** | 弹出输入框 |
| 2 | 输入群组 ID `1`，确认 | Bob 服务器窗口显示"已加入群组 1"，好友列表出现 `群组 1` |

### 6.3 群聊消息广播

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **Alice**：在好友列表中点击 `群组 1` | 聊天标题变为"与 群组 1 的聊天" |
| 2 | 输入 `大家好！`，点击发送 | Alice 看到自己发送的消息 |
| 3 | **Bob**：点击 `群组 1` | 看到 `alice: 大家好！` |

### 6.4 群聊消息撤回

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | Alice 在群组中发一条消息 `test recall` | — |
| 2 | **立刻**点击该消息文字（在聊天区域点击消息行） | 弹窗"是否撤回消息 xxx？" |
| 3 | 点击 **是** | Alice 和 Bob 的群组窗口中原消息变为"alice: [消息已撤回]" |

---

## 7. 阶段六：文件传输

### 7.1 私聊文件（接受）

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 准备测试文件：`echo "test content" > files/test.txt` | — |
| 2 | **Alice**：选择好友 bob，点击 **发送文件** | 弹出文件选择器 |
| 3 | 选择 `files/test.txt` | Alice 窗口显示"已发送文件: test.txt (13 bytes) [sent]" |
| 4 | **Bob**：弹窗"alice 希望发送文件 test.txt (13 bytes)，是否接受？" | — |
| 5 | Bob 点击 **是** | Bob 窗口显示收到文件，文件保存到 `files/recv_test.txt` |

**验证**:

```bash
cat files/recv_test.txt    # 应输出 "test content"
```

### 7.2 私聊文件（拒绝）

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | Alice 再向 Bob 发一个文件 | Bob 弹窗 |
| 2 | Bob 点击 **否** | Alice 服务器窗口显示"用户 bob 已拒绝文件 xxx" |

### 7.3 群组文件

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | Alice 选择 `群组 1`，点击发送文件，选一个文件发送 | — |
| 2 | Bob 弹窗"alice 在群组 开发小组 发送文件..." | — |
| 3 | Bob 接受 | 文件传输成功 |

---

## 8. 阶段七：消息撤回

### 8.1 撤回自己的消息（2分钟内有效）

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | Alice 给 Bob 发一条消息 `secret` | 记下 message_id |
| 2 | **立刻**点击 Alice 聊天窗口中这条消息 | 弹窗"是否撤回消息 xxx？" |
| 3 | 点击 **是** | Alice 的消息变为"alice: [消息已撤回] (message_id)" |
| 4 | Bob 窗口 | Bob 的消息也变为"alice: [消息已撤回]" |

### 8.2 撤回他人消息被阻止

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **Bob** 点击 Alice 发的一条消息 | 弹窗"只能撤回自己的消息" |

---

## 9. 阶段八：管理员功能

### 9.1 创建管理员账号

```bash
cd ~/PycharmProjects/chatroom
source .venv/bin/activate
python -c "
from database import Database
import bcrypt
db = Database()
pw = bcrypt.hashpw(b'admin123', bcrypt.gensalt())
db.add_user('admin', pw)
import sqlite3
conn = sqlite3.connect('users.db')
conn.execute(\"UPDATE users SET is_admin = 1 WHERE username = 'admin'\")
conn.commit()
conn.close()
print('管理员 admin 已创建，密码 admin123')
"
```

### 9.2 管理员登录

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 启动新客户端，用 `admin` / `admin123` 登录 | 弹窗"管理员登录成功！" |
| 2 | 界面右上角出现 **管理面板** 按钮 | — |

### 9.3 查看所有用户

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 点击 **管理面板** → **查看所有用户** | 弹出表格显示 alice、bob、admin，标注在线状态和是否管理员 |

### 9.4 发送系统公告

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **管理面板** → **发送公告** | 弹出输入框 |
| 2 | 输入 `系统将于今晚维护` | — |
| 3 | **Alice 和 Bob 客户端** | 自动切换到"服务器"聊天窗口，弹窗显示公告内容，消息红色加粗显示 |

### 9.5 删除用户

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | **管理面板** → **删除用户** | 弹出输入框 |
| 2 | 输入要删除的用户名（如 `charlie`），确认 | 用户被删除 |
| 3 | 查看用户列表 | charlie 已不在列表中 |

---

## 10. 阶段九：消息历史持久化验证

### 10.1 客户端行为

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 关闭所有客户端（alice、bob、admin） | — |
| 2 | **不要关闭服务端** | 服务端持续运行 |
| 3 | 重新启动 alice 客户端，登录 | — |
| 4 | 选择一个之前聊过的好友 | 聊天区域**应为空**（当前 tkinter 客户端未实现拉取历史 UI） |

> ⚠️ **注意**: 消息历史持久化已实现在服务端数据库层（`message_history` 表），但 tkinter 客户端 GUI 尚未接入"拉取历史"的 UI 交互（向上滚动自动加载）。这是阶段 3（Flutter 客户端）的工作。

### 10.2 直接验证数据库

```bash
cd ~/PycharmProjects/chatroom
sqlite3 users.db "SELECT sender, receiver, message_type, substr(CAST(content AS TEXT), 1, 40), message_id, timestamp FROM message_history ORDER BY timestamp DESC LIMIT 10;"
```

**预期**: 看到之前测试中发送的私聊、群聊消息记录，包括：

- `alice → bob [chat] "Hello Bob!"`
- `bob → alice [chat] "Hi Alice!"`
- `alice → bob [chat] "Are you there?"`
- `alice → [group_chat] "大家好！"`（group_id 非 NULL）
- `alice → [group_chat] "test recall"`（群聊撤回的消息依然在历史中）

---

## 11. 阶段十：配置文件验证

### 11.1 修改端口后生效

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | 停止服务端（Ctrl+C） | — |
| 2 | 编辑 `config.yaml`，把 `server.port` 改为 `8091` | — |
| 3 | 重启服务端 | 监听 127.0.0.1:**8091** |
| 4 | 编辑 `config.yaml`，`client.port` 也改为 `8091` | — |
| 5 | 启动客户端，登录 | 能正常连接到 8091 端口 |
| 6 | 改回 `8090`，重启服务端和客户端 | 恢复正常 |

### 11.2 配置文件缺失回退默认值

```bash
mv config.yaml config.yaml.bak
python server/server_main.py   # 应正常启动，使用默认值（127.0.0.1:8090）
# 看到 "服务器启动，监听 127.0.0.1:8090"，Ctrl+C 停止
mv config.yaml.bak config.yaml
```

---

## 12. 阶段十一：文件过期清理验证

```bash
cd ~/PycharmProjects/chatroom
sqlite3 users.db "INSERT INTO file_requests (message_id, sender, receiver, filename, filesize, content, timestamp) VALUES ('test-old-fr', 'alice', 'bob', 'old.txt', 10, X'74657374', '2020-01-01 00:00:00');"

# 重启服务端
python server/server_main.py
```

**预期日志**:

```
[INFO] 清理过期文件请求: 私聊=1, 群组=0, 合计=1
[INFO] 启动时清理了 1 个过期文件请求
```

---

## 13. 完整测试清单

| # | 测试项 | ☐ |
|---|--------|----|
| 1 | 自动化测试 151 passed | ☐ |
| 2 | SSL 证书生成 | ☐ |
| 3 | 服务端启动 | ☐ |
| 4 | 正常注册（合法用户名+密码） | ☐ |
| 5 | 客户端预验证——短用户名（<3字符） | ☐ |
| 6 | 客户端预验证——非法字符（SQL注入） | ☐ |
| 7 | 客户端预验证——短密码（<6字符） | ☐ |
| 8 | 重复注册被拒绝 | ☐ |
| 9 | 正常登录 | ☐ |
| 10 | 错误密码登录被拒 | ☐ |
| 11 | 登录不存在的用户被拒 | ☐ |
| 12 | 添加好友 + 在线通知 | ☐ |
| 13 | 接受好友请求 | ☐ |
| 14 | 拒绝好友请求 | ☐ |
| 15 | 向不存在用户发好友请求 | ☐ |
| 16 | 向自己发好友请求被阻止 | ☐ |
| 17 | 在线私聊（好友） | ☐ |
| 18 | 消息回执状态流转（sent → delivered） | ☐ |
| 19 | 向非好友发消息被阻止 | ☐ |
| 20 | 离线消息投递 | ☐ |
| 21 | 创建群组 | ☐ |
| 22 | 加入群组 | ☐ |
| 23 | 群聊消息广播到所有成员 | ☐ |
| 24 | 群聊消息撤回 | ☐ |
| 25 | 私聊文件传输（请求→接受→接收） | ☐ |
| 26 | 私聊文件传输（请求→拒绝） | ☐ |
| 27 | 群组文件传输 | ☐ |
| 28 | 撤回自己的消息（2分钟内） | ☐ |
| 29 | 撤回他人消息被阻止 | ☐ |
| 30 | 管理员登录 | ☐ |
| 31 | 查看所有用户 | ☐ |
| 32 | 发送系统公告 | ☐ |
| 33 | 删除用户 | ☐ |
| 34 | 消息历史写入数据库验证 | ☐ |
| 35 | config.yaml 修改端口生效 | ☐ |
| 36 | config.yaml 缺失回退默认值 | ☐ |
| 37 | 过期文件请求启动清理 | ☐ |

---

## 14. 快速 SQL 验证命令

```bash
# 查看已注册用户
sqlite3 users.db "SELECT username, is_admin FROM users;"

# 查看好友关系
sqlite3 users.db "SELECT user1, user2, status FROM friends;"

# 查看消息历史（最近 20 条）
sqlite3 users.db "SELECT sender, message_type, substr(CAST(content AS TEXT),1,50), timestamp FROM message_history ORDER BY id DESC LIMIT 20;"

# 查看待处理的文件请求
sqlite3 users.db "SELECT sender, receiver, filename, timestamp FROM file_requests;"

# 查看群组信息
sqlite3 users.db "SELECT g.id, g.group_name, COUNT(gm.username) as members FROM groups g JOIN group_members gm ON g.id=gm.group_id GROUP BY g.id;"

# 查看离线消息
sqlite3 users.db "SELECT sender, receiver, message_type, status, timestamp FROM offline_messages;"

# 统计各表行数
sqlite3 users.db "SELECT 'users', COUNT(*) FROM users UNION ALL SELECT 'message_history', COUNT(*) FROM message_history UNION ALL SELECT 'friends', COUNT(*) FROM friends UNION ALL SELECT 'offline_messages', COUNT(*) FROM offline_messages UNION ALL SELECT 'file_requests', COUNT(*) FROM file_requests UNION ALL SELECT 'groups', COUNT(*) FROM groups;"

# 按关键字搜索消息历史
sqlite3 users.db "SELECT sender, message_type, CAST(content AS TEXT), timestamp FROM message_history WHERE CAST(content AS TEXT) LIKE '%Hello%' ORDER BY timestamp DESC;"
```
