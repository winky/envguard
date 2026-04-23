# アーキテクチャ設計

---

## 1. モジュール構成

```
envguard/
├── main.go
├── go.mod
├── internal/
│   ├── patterns/
│   │   └── patterns.go      # キーワード・正規表現・リスク分類ルール
│   ├── masking/
│   │   └── masking.go       # 値マスキング処理
│   ├── scanner/
│   │   ├── base.go          # Scanner インターフェース、Finding 構造体
│   │   ├── env.go           # FR-1: 環境変数
│   │   ├── shellconfig.go   # FR-2: シェル設定ファイル
│   │   ├── credfiles.go     # FR-3: 認証ファイル
│   │   ├── launchctl.go     # FR-4: launchctl（macOS 専用）
│   │   ├── launchagents.go  # FR-5: LaunchAgent plist（macOS 専用）
│   │   └── direnv.go        # FR-6: .envrc
│   ├── classifier/
│   │   └── classifier.go    # FR-7: Finding にリスクレベルを付与
│   ├── reporter/
│   │   ├── text.go          # テキスト出力
│   │   └── json.go          # JSON 出力
│   └── advice/
│       └── advice.go        # FR-10: 対策提案
└── cmd/
    └── root.go              # flag パース、メインフロー
```

---

## 2. データモデル

`internal/scanner/base.go` に定義する。

```go
package scanner

type Risk string

const (
    RiskCritical Risk = "critical"
    RiskHigh     Risk = "high"
    RiskMedium   Risk = "medium"
    RiskLow      Risk = "low"
    RiskInfo     Risk = "info"
)

type Source string

const (
    SourceEnv            Source = "env"
    SourceShellConfig    Source = "shell_config"
    SourceCredentialFile Source = "credential_file"
    SourceLaunchctl      Source = "launchctl"
    SourceLaunchAgent    Source = "launch_agent"
    SourceDirenv         Source = "direnv"
)

type Finding struct {
    Source      Source  `json:"source"`
    Key         string  `json:"key"`
    MaskedValue *string `json:"masked_value"` // 認証ファイルは nil
    Location    string  `json:"location"`      // 例: "/Users/alice/.zshrc:42"
    Risk        Risk    `json:"risk"`
    Note        *string `json:"note,omitempty"`
}

type Scanner interface {
    Scan() ([]Finding, error)
}
```

---

## 3. 処理フロー

```
cmd/root.go
  │
  ├─ flag パース（--skip / --only / --json 等）
  │
  ├─ Scanner を順次実行 → []Finding を収集
  │     env.go / shellconfig.go / credfiles.go
  │     launchctl.go / launchagents.go / direnv.go
  │     （macOS 専用スキャナは runtime.GOOS == "darwin" の場合のみ実行）
  │
  ├─ classifier.go：各 Finding に Risk を付与
  │
  ├─ reporter/text.go または reporter/json.go で整形・出力
  │
  ├─ advice.go：Findings を見て対策テキストを追加
  │
  └─ 終了コードで終了（0 / 1 / 2）
```

---

## 4. エラー処理

| ケース | 挙動 |
|--------|------|
| 設定ファイルが存在しない | 何も報告せず次へ |
| ファイルの読み取り権限なし | stderr に `[WARN] <scanner>: <reason>` を出力し当該ファイルをスキップ |
| `launchctl` コマンドが存在しない | スキャナ全体をスキップ、サマリに「skipped」と表示 |
| plist のパース失敗 | `[WARN]` ログのみ、他の plist は継続処理 |
| `.envrc` 走査タイムアウト | 部分結果で継続、`[WARN]` 表示 |
| `--skip` と `--only` の同時指定 | エラーメッセージを表示し終了コード 2 で終了 |

例外は必ず握りつぶさず、最低でも stderr に `[WARN] <scanner>: <reason>` 形式で記録する。クラッシュはしない。

---

## 5. 実装マイルストーン

| フェーズ | 内容 | 完了条件 |
|----------|------|----------|
| M1 | プロジェクト骨格 + `patterns.py` + `masking.py` + `Finding` データクラス | 単体テストが green |
| M2 | `scanners/env.py` + テキスト reporter 最小版 | `envguard` で環境変数スキャンが動く |
| M3 | `scanners/shell_config.py` | `.zshrc` fixture で期待通り検出（export あり/なし両方） |
| M4 | `scanners/credential_files.py` + `launchctl.py` + `launch_agents.py` | macOS 実機で手動確認 + launchctl モックテスト green |
| M5 | `scanners/direnv.py`（タイムアウト込み） | 深さ・除外ルール動作確認 |
| M6 | JSON reporter + `advice.py` + CLI オプション完成 | `--json` がスキーマ通り、`--skip` / `--only` 排他制御動作 |
| M7 | README（制限事項含む）、インストーラ、統合テスト | end-to-end テスト green |

---

## 6. 実装上の注意点

1. **検出はパターン一致方式**。未知のベンダーでも `*_TOKEN` を拾えるよう語尾条件でマッチする
2. **値は一切ログに出さない**。マスクしてから `Finding` に載せる。内部の中間変数にも平文を保持しない（Python の GC により完全保証はできないことを認識する）
3. **ネットワーク送信を絶対にしない**。本ツールは完全ローカルで完結する
4. **`.envrc` の内容を実行しない**。正規表現による静的解析のみ。`direnv` コマンドは呼ばない
5. **`subprocess` 使用時は必ず `shell=False`** にし、引数はリスト形式で渡す
6. **カラー出力は TTY 判定**（`sys.stdout.isatty()`）で自動切替。`--no-color` と `NO_COLOR` 環境変数の両方に対応する
7. **終了コードを CI で使えるように厳密に**実装する（`requirement.md` セクション 5 参照）
8. **パターン定義はデータ駆動**にする。将来 YAML/TOML へ外出し可能な構造を意識する

---

## 7. 将来拡張（初版スコープ外）

- fish shell 対応（`~/.config/fish/config.fish`）
- `--fix` モードで `.zshrc` に自動で `unset` を追記（dry-run 必須）
- Linux 固有スキャナ（systemd environment、`/etc/environment` 等）
- Windows 対応（レジストリ環境変数等）
- Keychain メタデータ（項目名のみ）列挙
- HomeBrew Formula 化
- GitHub Actions 用のアクションラッパー
- `~/.gitconfig` の credential helper 設定スキャン
