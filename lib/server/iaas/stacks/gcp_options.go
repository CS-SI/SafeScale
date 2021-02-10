package stacks

// GCPConfiguration stores Google cloud platform configuration
type GCPConfiguration struct {
	Type         string `json:"type" validate:"required"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	AuthURI      string `json:"auth_uri"`
	TokenURI     string `json:"token_uri"`
	AuthProvider string `json:"auth_provider_x509_cert_url"`
	ClientCert   string `json:"client_x509_cert_url"`
	Region       string `json:"-"`
	Zone         string `json:"-"`
	NetworkName  string `json:"-"`
}
