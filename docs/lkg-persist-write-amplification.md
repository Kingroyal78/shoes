# LKG 落盘写放大：一次落盘 ~500 万次 write()，把 CPU 钉在 sys 态

- 版本：v0.3.16
- 结论：**缺陷在 `src/v2board/lkg.rs::persist_blocking()`** —— msgpack 快照直接写未缓冲的
  `File`，每个字段一次 `write()`。不是数据面、不是增量同步、不是内存。
- 影响：用户列表每次变更后落盘一次（实测 ≈2 次/分钟）。写路径快的机器只表现为 1–2 秒
  尖峰；写路径慢的 VPS 上这个 syscall 风暴持续 20–30 秒，叠加下一次落盘即长期 100%。
- 状态：**已实现两级修复，待灰度验证**。v0.3.17 加入 1 MiB 缓冲；后续版本把
  用户 delta 改为带 revision、长度和 CRC 的追加 journal，正常增量不再重写完整快照。

## 1. 现象

多台机器 load 远超核数，且与节点规模无关：

| 主机 | load (1/5/15) | nproc | 每节点 CPU |
|---|---|---|---|
| eu-hz-node-02 | 13.31 / 11.62 / 10.06 | 4 | 31–69% |
| eu5 | 13.44 / 12.25 / 10.71 | 4 | 25–44% |
| eu6 | 14.36 / 12.38 / 10.44 | 4 | — |
| jp1 | 16.21 / 16.29 / 17.65 | 4 | `shoes-ss335` 339% |
| us1（同为 29.7 万用户） | 1.11 / 1.13 / 1.27 | 6 | 0.8–18% |
| netcup-eu-1（同为 29.7 万用户） | 1.83 / 1.58 / 1.83 | 4 | 1–2.6% |

同样 29.7 万用户、同样 ~21 次发布/10 分钟，eu5/eu-hz 的每个 `shoes` 进程持续吃
30–69% CPU，而 us1/netcup 几乎空闲 —— 说明不是用户规模，也不是业务流量。

## 2. 定位过程与证据

1. `docker stats` 瞬时值抖动极大（同一容器 0.97% → 60.9%）→ 周期性而非稳态。
2. 逐秒 CPU 与容器日志对齐：CPU 在两次 `published ...`（间隔 ~23 s）之间**几乎持续**；
   user/sys 拆分为 **user=5.2% / sys=49.5%** → 几乎全是内核态。
3. 逐线程：单个线程（tid 4009452）长期处于 **R** 状态，占 38.8%（其中 sys 35.2%）。
4. `/proc/<pid>/io` 累计写：

   | 主机/容器 | syscw/s | 备注 |
   |---|---|---|
   | eu5 `shoes-ss324` | **198,368** | 持续 |
   | eu-hz-node-02 `shoes-ss275` | **232,720** | 持续 |
   | us1 `shoes-ss248` | 空闲 5–14，落盘瞬间 **2,698,209** | 约 2 秒完成 |

5. 写量与文件对应：数据卷里 `v2board-lkg-shadowsocks-324.mpk` = **24,726,600 B**；
   测得 `write_bytes/s ≈ 918 KB/s`，与“每 ~24 s 落盘一次 24.7 MB”吻合。
6. 折算：**24.7 MB ÷ ~5.4M 次 write ≈ 4.6 字节/次调用**。

## 3. 根因

`src/v2board/lkg.rs`（v0.3.16）：

```
 228  pub async fn persist(...)
 246      persist_blocking(&path, &snapshot)          // spawn_blocking
 277  fn persist_blocking(path, snapshot) {
 ...
 299      let mut file = options.open(&temporary)?;    // 未缓冲的 std::fs::File
 300      let write_result = (|| {
 301          rmp_serde::encode::write_named(&mut file, snapshot)
 303          file.sync_all()?;
 305          std::fs::rename(&temporary, path)?;
 ...
```

`rmp_serde` 每输出一个 msgpack token/字段就调用一次 `Write::write`，而目标是未缓冲的
`File`，因此：

- 29.7 万用户 × 约 18 个字段 ≈ **500 万次 `write()` 系统调用**写一个文件；
- 之后 `file.sync_all()` 再把 24.7 MB 刷盘。

触发时机：用户列表一旦变化就走 `applied_generation → persist_lkg()`。实测
`published` ≈ 21 次/10 分钟（≈ 2 次/分钟），即**每 ~24–28 秒一次 500 万次 syscall 风暴**。

差异只来自“写路径快慢”：

| 主机 | 500 万次小写耗时 | 表现 |
|---|---|---|
| us1（快） | ~2 s | 只见 1–2 秒尖峰，平均 CPU 低 |
| eu5 / eu-hz-node-02 / jp1（慢） | 20–30 s | 风暴未结束下一次又开始 → sys CPU 长期 100% |

## 4. 修复

在编码外层加缓冲，`flush` 之后再 `sync_all`。语义、原子性（tmp + rename）、
权限（0600）、fsync 全部不变：

```rust
// src/v2board/lkg.rs:2  —— 需要 Write 才能 flush
use std::io::{Read, Write};

// persist_blocking() 内，替换第 299–303 行
let mut file = options.open(&temporary)?;
let write_result = (|| {
    // Buffered encode: rmp_serde emits one write() per scalar/field, which on a
    // 300k-user snapshot is millions of syscalls per persist. On hosts with a
    // slower write path that alone pins a core for the whole interval between
    // user-list changes; one buffered flush turns it into a handful of
    // megabyte-sized writes.
    {
        let mut writer = std::io::BufWriter::with_capacity(1 << 20, &mut file);
        rmp_serde::encode::write_named(&mut writer, snapshot)
            .map_err(|error| invalid_data(format!("failed to encode LKG snapshot: {error}")))?;
        writer.flush()?;
    }
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path)?;
    // ...（其余不变）
```

系统调用数：24.7 MB ÷ 1 MiB ≈ **25 次**（原 ~5,000,000 次）。内存代价：编码期间多 1 MiB。

## 5. 后续完整修复：base + delta journal

缓冲消除了数百万次 syscall，但每次用户变化仍会重新编码、写入并 `fsync` 整个约 25 MB
快照。当前实现保留 `.mpk` 作为 base；只有用户变化时，把小 delta 追加到同名
`.journal`：

- 每条记录携带 node identity、用户 revision、ETag、updated/removed；
- 使用长度前缀和 CRC，崩溃产生的截断尾会在恢复时忽略并截掉，后续记录不会被旧尾遮住；
- 文件和首次目录项都 `fsync`，不会用延迟落盘换取错误的撤销恢复语义；
- 启动时先读 base，再按 revision 重放 journal；base 已包含的记录会跳过；
- journal 达到 8 MiB，或 server/plugin/full-users 变化时，原子生成新 base 并清理 journal。

因此常规 mgcors 小 delta 的写入从约 25 MB 降为几百字节到几 KB；完整快照只在全量变化
或压缩时生成。

## 6. 预期效果

- 单节点落盘 CPU：慢盘从 20–30 s 降到 <1 s（剩余时间主要是 `sync_all()` 的 I/O，不是 CPU）。
- eu5 / eu-hz-node-02 / eu6 / jp1 的 load 应回落到接近 us1 的水平。
- 恢复内容和撤销语义不变；完整快照频率显著下降，日常 delta 以 journal 持久化。

## 7. 验证方法

1. 灰度一台忙机（如 eu5 的 `shoes-ss324`）：
   ```
   # 逐秒 syscw，落盘瞬间峰值应 < 1000/s（原来是 200,000–2,700,000/s）
   grep syscw /proc/$(docker inspect -f '{{.State.Pid}}' shoes-ss324)/io
   ```
2. 逐秒 CPU 曲线应从“持续 30–50%”变成“发布时 1–2 s 尖峰 + 其余空闲”。
3. `cargo test --bin shoes -- v2board::lkg`
   （round-trip / 原子性 / owner-only 权限 / 跨 32 MiB 上限）。
4. 观察 24–48 h 的 load 与首个落盘周期。

## 8. 附带建议

- `traffic-pending.json` 也是小写入（每次约 +100 B），量大时同样可考虑缓冲/合并。
- 复核 `applied_generation` 的判定：确认“仅 revision 前进、用户内容未变”的拉取不会
  触发无谓落盘。

## 附：本次使用的主要取证命令

```sh
# 负载 / 逐进程 CPU
cat /proc/loadavg; ps -eo pcpu,pmem,comm --sort=-pcpu | head
# 稳态 CPU（读 /proc/<pid>/stat 的 utime+stime 差值）
#   见 /root/cpu-steady.py
# 逐线程 / syscall / 写量
cat /proc/<pid>/task/<tid>/stat; cat /proc/<pid>/task/<tid>/syscall
grep -E 'syscr|syscw|write_bytes' /proc/<pid>/io
# 逐秒 syscw 与 LKG 文件增长
#   见 /root/tmpwatch.py
# 容器日志是否狂刷（排除“写 docker 日志”）
docker inspect -f '{{.Id}}' <container>   # -> /var/lib/docker/containers/<id>/<id>-json.log
```
