package patterns

import (
	"regexp"
	"strings"

	"github.com/winky/envguard/internal/model"
)

// PatternRule associates a compiled regular expression with a risk level.
type PatternRule struct {
	Pattern *regexp.Regexp
	Risk    model.Risk
}

// CRITICAL patterns
var criticalPatterns = []PatternRule{
	{regexp.MustCompile(`SECRET_ACCESS_KEY`), model.RiskCritical},
	{regexp.MustCompile(`.*_PRIVATE_KEY$`), model.RiskCritical},
	{regexp.MustCompile(`.*_CLIENT_SECRET$`), model.RiskCritical},
	{regexp.MustCompile(`.*_SECRET$`), model.RiskCritical},
	{regexp.MustCompile(`.*_PASSWORD$`), model.RiskCritical},
	{regexp.MustCompile(`^DATABASE_URL$`), model.RiskCritical},
	{regexp.MustCompile(`^POSTGRES_URL$`), model.RiskCritical},
	{regexp.MustCompile(`^MYSQL_URL$`), model.RiskCritical},
	{regexp.MustCompile(`^MONGODB_URI$`), model.RiskCritical},
	{regexp.MustCompile(`^REDIS_URL$`), model.RiskCritical},
}

// HIGH patterns
var highPatterns = []PatternRule{
	{regexp.MustCompile(`.*_TOKEN$`), model.RiskHigh},
	{regexp.MustCompile(`.*_API_KEY$`), model.RiskHigh},
	{regexp.MustCompile(`.*_ACCESS_TOKEN$`), model.RiskHigh},
	{regexp.MustCompile(`^AWS_SESSION_TOKEN$`), model.RiskHigh},
	{regexp.MustCompile(`^GH_TOKEN$`), model.RiskHigh},
	{regexp.MustCompile(`^GITHUB_TOKEN$`), model.RiskHigh},
	{regexp.MustCompile(`^GITLAB_TOKEN$`), model.RiskHigh},
	{regexp.MustCompile(`^NPM_TOKEN$`), model.RiskHigh},
	{regexp.MustCompile(`^SLACK_TOKEN$`), model.RiskHigh},
	{regexp.MustCompile(`^STRIPE_SECRET_KEY$`), model.RiskHigh},
	{regexp.MustCompile(`^STRIPE_LIVE_KEY$`), model.RiskHigh},
	{regexp.MustCompile(`^OPENAI_API_KEY$`), model.RiskHigh},
	{regexp.MustCompile(`^ANTHROPIC_API_KEY$`), model.RiskHigh},
	{regexp.MustCompile(`^HF_TOKEN$`), model.RiskHigh},
	{regexp.MustCompile(`^VAULT_TOKEN$`), model.RiskHigh},
}

// MEDIUM patterns
var mediumPatterns = []PatternRule{
	{regexp.MustCompile(`^AWS_ACCESS_KEY_ID$`), model.RiskMedium},
	{regexp.MustCompile(`^AWS_PROFILE$`), model.RiskMedium},
	{regexp.MustCompile(`^AWS_ROLE_ARN$`), model.RiskMedium},
	{regexp.MustCompile(`^GOOGLE_APPLICATION_CREDENTIALS$`), model.RiskMedium},
	{regexp.MustCompile(`^GCLOUD_PROJECT$`), model.RiskMedium},
	{regexp.MustCompile(`^GOOGLE_CLOUD_PROJECT$`), model.RiskMedium},
	{regexp.MustCompile(`^AZURE_.*_ID$`), model.RiskMedium},
	{regexp.MustCompile(`^KUBECONFIG$`), model.RiskMedium},
	{regexp.MustCompile(`^DOCKER_AUTH_CONFIG$`), model.RiskMedium},
	{regexp.MustCompile(`^TF_VAR_.*`), model.RiskMedium},
}

// LOW patterns
var lowPatterns = []PatternRule{
	{regexp.MustCompile(`^AWS_REGION$`), model.RiskLow},
	{regexp.MustCompile(`^AWS_DEFAULT_REGION$`), model.RiskLow},
	{regexp.MustCompile(`^AWS_DEFAULT_OUTPUT$`), model.RiskLow},
	{regexp.MustCompile(`^GCLOUD_REGION$`), model.RiskLow},
}

// allPatterns ordered by severity (CRITICAL first).
var allPatterns = func() []PatternRule {
	var all []PatternRule
	all = append(all, criticalPatterns...)
	all = append(all, highPatterns...)
	all = append(all, mediumPatterns...)
	all = append(all, lowPatterns...)
	return all
}()

// Classify evaluates a key name against all patterns and returns the risk level.
// The key is uppercased before matching. Patterns are evaluated in order from
// CRITICAL to LOW; the first match wins.
// For TF_VAR_* keys, the suffix (after TF_VAR_) is re-evaluated against
// CRITICAL and HIGH patterns, and the higher risk is applied if matched.
func Classify(key string) (model.Risk, bool) {
	upper := strings.ToUpper(key)

	for _, rule := range allPatterns {
		if rule.Pattern.MatchString(upper) {
			// TF_VAR_* override logic
			if strings.HasPrefix(upper, "TF_VAR_") {
				suffix := strings.TrimPrefix(upper, "TF_VAR_")
				if overrideRisk, ok := classifyWithPatterns(suffix, criticalPatterns); ok {
					return overrideRisk, true
				}
				if overrideRisk, ok := classifyWithPatterns(suffix, highPatterns); ok {
					return overrideRisk, true
				}
			}
			return rule.Risk, true
		}
	}
	return "", false
}

// classifyWithPatterns checks the key against a specific set of patterns.
func classifyWithPatterns(key string, patterns []PatternRule) (model.Risk, bool) {
	for _, rule := range patterns {
		if rule.Pattern.MatchString(key) {
			return rule.Risk, true
		}
	}
	return "", false
}

// CredentialPath represents a known credential file path to check.
type CredentialPath struct {
	Path string
	Risk model.Risk
	Note string
}

// CredentialPaths is the list of known credential file paths.
var CredentialPaths = []CredentialPath{
	{"~/.aws/credentials", model.RiskCritical, "AWS CLI 認証情報"},
	{"~/.aws/config", model.RiskMedium, "AWS CLI 設定（プロファイル含む）"},
	{"~/.config/gcloud/credentials.db", model.RiskCritical, "gcloud 認証情報"},
	{"~/.config/gcloud/application_default_credentials.json", model.RiskCritical, "GCP ADC"},
	{"~/.azure/", model.RiskHigh, "Azure CLI"},
	{"~/.kube/config", model.RiskHigh, "Kubernetes クラスタ認証"},
	{"~/.docker/config.json", model.RiskHigh, "Docker レジストリ認証"},
	{"~/.config/gh/hosts.yml", model.RiskHigh, "GitHub CLI トークン"},
	{"~/.netrc", model.RiskHigh, "HTTP 認証情報"},
	{"~/.npmrc", model.RiskMedium, "npm トークン"},
	{"~/.pypirc", model.RiskMedium, "PyPI トークン"},
	{"~/.vault-token", model.RiskCritical, "HashiCorp Vault トークン"},
	{"~/.ssh/id_rsa", model.RiskHigh, "SSH 秘密鍵 (RSA)"},
	{"~/.ssh/id_ed25519", model.RiskHigh, "SSH 秘密鍵 (Ed25519)"},
	{"~/.ssh/id_ecdsa", model.RiskHigh, "SSH 秘密鍵 (ECDSA)"},
	{"~/.ssh/id_dsa", model.RiskHigh, "SSH 秘密鍵 (DSA)"},
}

// LaunchctlCandidates is the list of environment variable names to probe via launchctl getenv.
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
