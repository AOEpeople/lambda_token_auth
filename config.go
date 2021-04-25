package auth

// Config holds all configuration for the Handler
type Config struct {
	Bucket                string
	ObjectKey             string
	JwksURL               string `json:"jwks_url"`
	EnableRoleAnnotations bool   `json:"enable_role_annotations"`
	RoleAnnotationPrefix  string `json:"role_annotation_prefix"`
	Region                string `json:"region"`
	Duration              int64  `json:"duration"`
	Rules                 []Rule `json:"rules"`
}
