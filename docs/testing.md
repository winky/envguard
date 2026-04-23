# テスト方針

Go 標準の `testing` パッケージを使用する。テーブル駆動テストを基本スタイルとする。

---

## 1. 単体テスト

| ファイル | 内容 |
|---------|------|
| `internal/patterns/patterns_test.go` | キー名 → Risk 判定のテーブル駆動テスト（TF_VAR_* 上書きルール含む） |
| `internal/masking/masking_test.go` | 境界値（0 / 8 / 9 / 100 文字） |
| `internal/scanner/shellconfig_test.go` | 擬似 `.zshrc` fixture を読んで検出件数検証（`export` あり/なし両方） |
| `internal/scanner/launchagents_test.go` | 擬似 plist fixture を読んで検出検証 |
| `internal/reporter/reporter_test.go` | JSON スキーマ検証、テキストフォーマット検証 |
| `internal/scanner/launchctl_test.go` | `exec.Command` をモックして正常系・コマンド不在系を検証 |

---

## 2. 統合テスト

- `t.TempDir()` で fake な `$HOME` を構築し、end-to-end で `cmd.Run()` を呼ぶ
- 終了コード、stdout、stderr を検証

---

## 3. 手動受け入れテスト

1. クリーンな環境で実行 → `critical 0 / high 0 ...` になること
2. `export AWS_SECRET_ACCESS_KEY=dummy` してから実行 → CRITICAL 1 件として検出されること
3. `--json` 出力を `jq` でパース成功すること

---

## 4. ディレクトリ構成

```
envguard/
├── README.md
├── go.mod
├── main.go
├── cmd/
├── internal/
│   └── .../
│       └── *_test.go        # 各パッケージにテストを同梱
├── testdata/
│   ├── sample.zshrc
│   └── sample_agent.plist
└── scripts/
    └── install.sh
```

**配布形態:**

- シングルバイナリを GitHub Releases に添付（`curl` でダウンロードして即実行）
- `go install github.com/winky/envguard@latest` でも導入可能
- ビルドターゲット: `darwin/amd64`, `darwin/arm64`, `linux/amd64`, `linux/arm64`
