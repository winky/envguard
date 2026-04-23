# CLI・出力仕様

---

## 1. CLI オプション

```
envguard [OPTIONS]

OPTIONS:
  --json                  JSON 形式で出力
  --summary               件数のみ表示
  --no-color              ANSI カラー無効化（NO_COLOR 環境変数も有効）
  --skip SCANNER          特定スキャナをスキップ（複数指定可）
                          選択肢: env, shell, files, launchctl, agents, direnv
  --only SCANNER          指定スキャナのみ実行（--skip と排他、同時指定はエラー）
  --depth N               .envrc 走査の最大階層（デフォルト 4）
  --min-risk LEVEL        指定レベル以上のみ表示（critical/high/medium/low/info）
  --quiet                 進捗ログを抑止
  --version
  --help
```

### 使用例

```bash
# デフォルト実行
envguard

# CI で JSON を保存
envguard --json > scan-report.json

# CRITICAL と HIGH のみ素早く確認
envguard --min-risk high --skip direnv
```

---

## 2. テキスト出力

```
================================================================
  envguard レポート
  実行日時: 2026-04-23 14:30:00 JST
  ホスト: alice-macbook
================================================================

[CRITICAL] 2 件
  x AWS_SECRET_ACCESS_KEY
      場所: 環境変数（現在のシェル）
      値:   ****wXyZ
  x GITHUB_TOKEN
      場所: /Users/alice/.zshrc:42
      値:   ****abcd

[HIGH] 1 件
  ! OPENAI_API_KEY
      場所: launchctl setenv
      値:   ****9f2e

[INFO] 3 件
  . ~/.aws/credentials (2.1KB, 更新 2026-03-15)
  . ~/.kube/config (8.4KB, 更新 2026-04-20)
  . ~/.config/gh/hosts.yml (412B, 更新 2026-04-01)

----------------------------------------------------------------
サマリ: CRITICAL 2 / HIGH 1 / MEDIUM 0 / LOW 0 / INFO 3
----------------------------------------------------------------

[注意] .envrc の動的構文（コマンド置換等）は検出対象外です

【推奨対策】
1. 環境変数をシェルから切り離す:
     env -i HOME="$HOME" PATH="$PATH" SHELL="$SHELL" claude
2. direnv で作業ディレクトリ単位に unset:
     # ~/work/claude-code/.envrc
     unset AWS_SECRET_ACCESS_KEY GITHUB_TOKEN OPENAI_API_KEY
3. 長期クレデンシャルは aws-vault / 1Password CLI へ移行検討
```

---

## 3. JSON 出力スキーマ

```json
{
  "schema_version": "1.1",
  "generated_at": "2026-04-23T14:30:00+09:00",
  "host": "alice-macbook",
  "summary": {
    "critical": 2, "high": 1, "medium": 0, "low": 0, "info": 3
  },
  "findings": [
    {
      "source": "env",
      "key": "AWS_SECRET_ACCESS_KEY",
      "masked_value": "****wXyZ",
      "location": "environ",
      "risk": "critical",
      "note": null
    }
  ],
  "advice": [
    {
      "id": "env-isolation",
      "title": "env -i で起動",
      "command": "env -i HOME=\"$HOME\" PATH=\"$PATH\" SHELL=\"$SHELL\" claude"
    }
  ],
  "warnings": [
    ".envrc の動的構文（コマンド置換等）は検出対象外です"
  ]
}
```

---

## 4. 終了コード

| コード | 意味 |
|--------|------|
| `0` | 何も検出されず |
| `1` | 検出あり |
| `2` | 実行エラー（引数不正・権限エラー等） |
