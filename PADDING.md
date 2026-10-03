# EDNS(0) Padding 对齐说明（RFC 7830）

## 新增 API

```go
func (dns *Msg) PreparePadding(blockSize int, maxSize int) error
```

- `blockSize`：对齐块大小（如 128），最终 `Pack()` 出的报文长度是它的整数倍。必须 > 0，
  否则返回 `ErrPaddingBlockSize`。
- `maxSize`：允许的最大报文字节数。> 0 时若对齐后超长，返回 `ErrPaddingTooLarge` 且原
  `Msg` 不变；传 0 或负数表示不限制。
- 消息中存在多个 OPT 伪记录时返回 `ErrPaddingMultipleOPT`，不会隐式挑选其中一个。

## 行为要点

1. **沿真实 Pack 计算**：先移除已有 PADDING，再用与最终编码完全相同的压缩设置（`Msg.Compress`）
   实际 `Pack()` 一次，以真实未填充长度计算 padding，而不是按字段长度估算。
2. **计入选项头**：padding 长度按 `未填充长度 + 4`（PADDING 的 code+length 选项头）计算：
   `padLen = blockSize - (len(unpadded)+4) % blockSize`，余数为 0 时 `padLen = 0`（只带
   4 字节选项头）。因此已经对齐的消息再次准备时仍停留在边界上，不会因为多加选项头而偏离。
3. **顺序保留**：OPT 伪记录在 additional 段中的位置、其余 EDNS 选项的顺序均不变；旧 PADDING
   先移除，新 PADDING 按 RFC 7830 建议追加到选项末尾，填充字节为 0。
4. **无 OPT 自动创建**：消息没有 OPT 时新建一个（若存在 TSIG，则插在 TSIG 之前，保证 TSIG
   仍是 additional 段最后一条）。
5. **失败不留半成品**：所有改动都在深拷贝上进行，只有 Pack 成功、对齐且未超长时才整体提交
   回接收者；任何错误路径上原 `Msg` 的 Pack 结果保持不变。
6. **幂等**：对已准备好的消息再次调用，会移除旧 PADDING 重新计算，最终 Pack 字节与上次一致。

## 演示（打印报文长度）

`ExampleMsg_PreparePadding`（见 `example_test.go`）构造一个含 NSID 与 COOKIE 两个 EDNS
选项的压缩查询，输出：

```text
before=61 after=128 aligned=true
```

运行：

```sh
go test -run 'ExampleMsg_PreparePadding' -v .
go test -run 'TestPreparePadding' -v .
```

## 测试覆盖（`edns_padding_test.go`）

- 含压缩域名 + NSID/COOKIE 两选项：Pack 长度整除块大小、重复准备字节一致；
- 选项顺序与 OPT 头字段（DO、UDPSize）保留；
- 已有（超大、非零、位于选项中间的）PADDING 被移除并重新计算；
- 无 OPT 的消息自动创建 OPT 并对齐；
- TSIG 存在时 OPT 插在其前、TSIG 仍在最后；
- 已对齐消息再次准备不偏离边界且字节不变；
- `blockSize == 0`/负数、多个 OPT 明确报错且消息不变（不多选、不隐式选择）；
- `maxSize` 不足时报 `ErrPaddingTooLarge`，原 Msg 不变；放宽上限后成功。
