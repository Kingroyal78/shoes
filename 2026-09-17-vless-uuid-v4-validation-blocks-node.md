# VLESS 节点曾因 UUID v4 限制拒绝首次同步（已修复）

- 日期：2026-09-17
- 发现于：将一个生产 VLESS 节点从 v2bx 后端迁移到 shoes 时
- 影响：首次启动且没有可用 LKG 时，节点无法 ready；已有运行时会保留旧用户表
- 状态：已在 shoes 侧修复，本地回归通过；真实面板验收等待测试环境恢复

## 症状

shoes 容器启动后持续重试，节点始终不 ready：

```text
WARN shoes::app] node `<node-tag>` initial sync failed; controller will keep retrying:
  node `<node-tag>` user <user-id> has invalid VLESS uuid:
  UUID is not version 4
INFO shoes::app] shoes V2Board backend running with 1 controller(s), 0 initially ready
```

同一份用户列表由 v2bx（sing-box）处理时可以正常启动。

## 根因

`src/uuid_util.rs` 原来的 `parse_uuid()` 同时承担了两种职责：

1. 将 UUID 文本解码为 16 字节；
2. 强制版本为 v4、variant 为 RFC 4122。

VLESS 的线上用户 ID 是 16 字节值，并不要求只能使用 UUID v4。现场的两个凭据是语法和
variant 均有效的 UUID v1，因此能被其它 VLESS 实现接受，却被 shoes 的额外生成策略限制拒绝。

V2Board 映射会在构建用户表前验证所有 VLESS 用户。首次启动没有 LKG 时，任一用户验证失败都会
使候选运行时构建失败，节点保持 0 ready。节点已经运行时，失败的用户清单不会被发布，旧用户表
仍然生效。

## 现场数据

生产面板返回约 1.96 万个 VLESS 用户，其中只有两个相邻用户使用 UUID v1，其余为 UUID v4。
生产面板地址、节点标识、用户标识和完整凭据均不记录在本文档中。

## 修复

shoes 现在区分 UUID 生成策略和 VLESS 协议解析：

- 新增 `parse_vless_uuid()`，接受带或不带横线的 32 个十六进制数字，不限制 UUID 版本或 variant；
- VLESS 服务端、客户端、Vision、V2Board 映射和旧配置校验统一使用该解析器；
- 原 `parse_uuid()` 继续强制 UUID v4，避免无意改变 TUIC、VMess 等其它协议的既有行为；
- `generate_uuid()` 继续生成 UUID v4；
- 畸形 VLESS 凭据仍会使候选用户表构建失败，不会静默跳过用户；
- 错误文本和 VLESS 客户端 `Debug` 输出不再包含完整凭据。

这里不增加 `lenient_uuid` 开关：接受其它 UUID 版本是 VLESS 协议兼容行为，不是降低验证强度。
“遇到真正畸形用户时是否跳过”属于独立的可用性策略，不与本次兼容性修复混合。

## 回归覆盖

- V2Board VLESS 运行时接受 UUID v1；
- VLESS 解析接受 UUID v1 和 v5；
- 新增实面板矩阵用例，用外部 singlink 客户端验证 UUID v1 的握手、转发和流量上报；
- 原通用解析器仍拒绝非 v4 UUID 和错误 variant；
- 畸形 VLESS UUID 仍被拒绝；
- 映射错误和客户端调试输出不会回显凭据。

本地 `cargo test`、格式检查、全目标 Clippy 和矩阵脚本 ShellCheck 已通过。真实面板用例在预检时
被测试栈阻塞：面板容器运行 PHP 7.4，而当前 Composer 依赖要求 PHP 8.2，因此根路径返回 500；
用例尚未进入夹具写入或 shoes 启动阶段，不能记为通过。

## 部署验证

1. 节点日志出现 `running with 1 controller(s), 1 initially ready`；
2. 入口经 CDN WebSocket 握手返回 `101`；
3. 面板显示节点可用并产生在线数据；
4. 分别抽查一个 UUID v1 用户和一个 UUID v4 用户的真实连通性；
5. 检查日志，确认失败消息不包含完整用户凭据。

## 相关文件

- `src/uuid_util.rs`：通用 UUID v4 与 VLESS 16 字节 ID 的解析边界
- `src/v2board/mapper.rs`：V2Board VLESS 用户映射和回归测试
- `src/vless/vless_server_handler.rs`：VLESS 用户表
- `src/vless/vless_client_handler.rs`：VLESS 客户端解析和调试脱敏
- `src/config/validate.rs`、`src/tcp/tcp_*_handler_factory.rs`：旧本地配置兼容路径
