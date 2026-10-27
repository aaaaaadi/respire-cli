# 独立日记片段检索

日记可能包含提议、失败尝试与未确认结论。本入口只提供可定位的历史参考，不改变普通 `recall`，不自动提升日记、不改写主记忆，也不根据正文中的“验证通过”等字样认定事实可信。

## 命令与返回

```text
rsrs --client-only --json diary-search "物联网接入" --mode hybrid --limit 5 --max-chars 4000
rsrs --client-only --json diary-search "港珠澳" --mode lexical --limit 5 --max-chars 4000
rsrs --client-only --json diary-fragment <source-id> <fragment-id> --neighbors 1 --max-chars 4000
```

MCP 对应 `memory_diary_search`（query、mode、limit、max_chars）及 `memory_diary_fragment`（source_id、fragment_id、neighbors、max_chars）。只读模式允许读取，暂停模式仍拒绝读取；既有授权策略不变。旧 Runtime 不识别新命令时会报错，调用方应明确提示能力尚未安装，不应把旧的整日输出包装成片段语义检索。

JSON 信封中的 `details.items` 是结果。每项包含：

- `source_kind=diary`、`evidence_state=reference`：来源和保守的参考状态，不是验证凭据。
- `source_id`、`fragment_id`、`source_version`：原记忆 ID、片段定位 ID、当前加密记录的 SHA-256 版本指纹。
- `date`、`title`、`project`：本地日期与有限长度的出处信息。
- `start`、`end`：原文 Unicode 标量的半开区间；不是 UTF-8 字节或 JavaScript UTF-16 下标。
- `text`、`truncated`、`score`：有界正文、是否截断和排序分数。分数只表示相关性，不表示可信度。

`details.semantic_ready` 和 `pending_fragments` 区分语义索引完整或待建立；索引缺失时仍可返回词面命中，并通知既有后台索引器。查询不在前台为整年日记生成全部向量。读取片段最多包含前后各一段，先为目标片段分配预算，再按剩余预算读取邻段；输出恢复原文顺序，省略或截断邻段时标记 `truncated=true`。片段内容、位置或索引元数据改变后，旧定位 ID 会被拒绝，要求重新搜索。原文末尾追加不影响内容与位置都未变的既有片段。

`limit` 为 1–20，`max_chars` 为 512–12000，默认分别 5、4000。预算约束紧凑序列化后的 `details` 字符数，包含片段元数据和 JSON 转义；外层标准信封另有固定开销。这是字符预算，不是精确 token 数。预算不足时可能无可容纳的结果，`truncated=true`。非 JSON 模式直接输出相同的紧凑有界结果。

## 检索与派生索引

独立检索仅扫描当前账号中有效的 `trivial` 日记，不读取删除记录。词面检索解密完整正文，在记录边界分段后匹配所有查询词；不会只检查前 500 字符。长记录按最多 800 个 Unicode 标量切分，优先换行，保留 80 字符重叠。词面查询仍会在本地扫描全部日记，磁盘和本地计算成本与数据量有关；完整日记不会因此返回给对话模型。

语义路径调用公开 Core SDK 的 BGE-M3 `prepare`、`query` 与索引状态接口。后台索引器在既有取消、账号切换与前台让路机制下更新派生缓存。当前账号数据目录中的 `diary-fragments-v1.db` 只保存来源版本与 Core 不透明索引定位，不保存额外的日记明文。Core 派生工件继续由其现有本地索引机制管理。新增/修改/删除、模型代际变化和失效工件会触发重建；不改变原记忆、同步历史或日记父节点。

已有 `diary --contains` 是全库时间链（包含主记忆与日记），与上述仅日记入口不同。它现改为解密全文过滤，并返回命中附近最多 500 字符摘要；原有日期、排序与数量语义保持。

## 当前验证边界

公开源码可以修改分段、CLI/MCP、返回边界、缓存和 SDK 调用编排；不可编辑闭源 Core 内部的向量算法与模型实现。构建必须提供仓库锁定的匹配 SDK，不能绕过 manifest 校验。

本机临时源码验证覆盖十万以上 Unicode 字符末尾命中、分段覆盖、响应字符预算、相邻读取、旧定位拒绝、参考来源标记及参数范围。它仅使用隔离内存数据，Core 调用刻意不可用，不代表真实模型验证。正式 `cargo check -p respire_app --no-default-features` 被缺少 `RSRS_CORE_SDK_DIR` 阻断；下载脚本要求隔离可信步骤中的 `CORE_SDK_READ_TOKEN`。新 Runtime 未构建、未部署，真实 BGE-M3 检索、MCP 往返、重启恢复和跨账号缓存隔离仍需匹配 SDK 后验收。
