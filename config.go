package auth

// Config holds all configuration for the Handler
type Config struct {
	JwksURL               string `json:"jwks_url"`
	EnableRoleAnnotations bool   `json:"enable_role_annotations"`
	Region                string `json:"region"`
	Duration              int64  `json:"duration"`
	Rules                 []Rule `json:"rules"`
}
