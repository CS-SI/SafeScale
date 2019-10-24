package stacks

// AWS cloud platform configuration
type AWSConfiguration struct {
	S3Endpoint  string `json:"-"`
	Ec2Endpoint string `json:"-"`
	SsmEndpoint string `json:"-"`
	Region      string `json:"-"`
	Zone        string `json:"-"`
}
