# 検出パターン定義

---

## 1. キーワードパターン

判定は「キー名を大文字化した後、いずれかの正規表現にマッチするか」。パターン定義はデータ駆動で保持し（`[]PatternRule` のスライス）、将来 YAML/TOML へ外出し可能な構造とする。

### CRITICAL

```
SECRET_ACCESS_KEY
.*_PRIVATE_KEY$
.*_CLIENT_SECRET$
.*_SECRET$
.*_PASSWORD$
DATABASE_URL
POSTGRES_URL
MYSQL_URL
MONGODB_URI
REDIS_URL
```

### HIGH

```
.*_TOKEN$
.*_API_KEY$
.*_ACCESS_TOKEN$
AWS_SESSION_TOKEN
GH_TOKEN
GITHUB_TOKEN
GITLAB_TOKEN
NPM_TOKEN
SLACK_TOKEN
STRIPE_SECRET_KEY
STRIPE_LIVE_KEY
OPENAI_API_KEY
ANTHROPIC_API_KEY
HF_TOKEN
VAULT_TOKEN
```

> `AWS_SESSION_TOKEN` は一時認証情報だが、有効期間中は本番フルアクセス可能なため HIGH とする。

### MEDIUM

```
AWS_ACCESS_KEY_ID
AWS_PROFILE
AWS_ROLE_ARN
GOOGLE_APPLICATION_CREDENTIALS
GCLOUD_PROJECT
GOOGLE_CLOUD_PROJECT
AZURE_.*_ID
KUBECONFIG
DOCKER_AUTH_CONFIG
TF_VAR_.*
```

### LOW

```
AWS_REGION
AWS_DEFAULT_REGION
AWS_DEFAULT_OUTPUT
GCLOUD_REGION
```

### TF_VAR_* の上書きルール

`TF_VAR_.*` にマッチした場合、キー名をさらに CRITICAL / HIGH パターンで評価し、マッチすればそちらのリスクレベルを適用する。

| 例 | 適用リスク |
|----|-----------|
| `TF_VAR_DB_PASSWORD` | CRITICAL |
| `TF_VAR_API_KEY` | HIGH |
| `TF_VAR_REGION` | MEDIUM（上書きなし） |

---

## 2. 認証ファイルの既定パス

```go
var CredentialPaths = []CredentialPath{
    {"~/.aws/credentials",                                    RiskCritical, "AWS CLI 認証情報"},
    {"~/.aws/config",                                         RiskMedium,   "AWS CLI 設定（プロファイル含む）"},
    {"~/.config/gcloud/credentials.db",                       RiskCritical, "gcloud 認証情報"},
    {"~/.config/gcloud/application_default_credentials.json", RiskCritical, "GCP ADC"},
    {"~/.azure/",                                             RiskHigh,     "Azure CLI"},
    {"~/.kube/config",                                        RiskHigh,     "Kubernetes クラスタ認証"},
    {"~/.docker/config.json",                                 RiskHigh,     "Docker レジストリ認証"},
    {"~/.config/gh/hosts.yml",                                RiskHigh,     "GitHub CLI トークン"},
    {"~/.netrc",                                              RiskHigh,     "HTTP 認証情報"},
    {"~/.npmrc",                                              RiskMedium,   "npm トークン"},
    {"~/.pypirc",                                             RiskMedium,   "PyPI トークン"},
    {"~/.vault-token",                                        RiskCritical, "HashiCorp Vault トークン"},
    {"~/.ssh/id_rsa",                                         RiskHigh,     "SSH 秘密鍵 (RSA)"},
    {"~/.ssh/id_ed25519",                                     RiskHigh,     "SSH 秘密鍵 (Ed25519)"},
    {"~/.ssh/id_ecdsa",                                       RiskHigh,     "SSH 秘密鍵 (ECDSA)"},
    {"~/.ssh/id_dsa",                                         RiskHigh,     "SSH 秘密鍵 (DSA)"},
}
```

`~/.ssh/` ディレクトリ自体ではなく個別の秘密鍵ファイルを対象とする（ディレクトリ存在のみでは判断できないため）。

---

## 3. launchctl 候補リスト

環境変数全列挙の API は無いため、以下の変数名を決め打ちで `launchctl getenv` する。

```go
var LaunchctlCandidates = []string{
    // AWS
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_REGION", "AWS_DEFAULT_REGION",
    // GCP
    "GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT",
    // Azure
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    // GitHub / GitLab
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
    // OpenAI / Anthropic
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    // HashiCorp
    "VAULT_TOKEN", "VAULT_ADDR",
    // npm / PyPI
    "NPM_TOKEN",
    // Kubernetes / Docker
    "KUBECONFIG", "DOCKER_AUTH_CONFIG",
    // Slack / Stripe
    "SLACK_TOKEN", "STRIPE_SECRET_KEY", "STRIPE_LIVE_KEY",
    // HuggingFace
    "HF_TOKEN",
    // Database
    "DATABASE_URL", "POSTGRES_URL", "MONGODB_URI", "REDIS_URL",
}
```
