package gcp

import (
	"context"
	"encoding/json"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

type StackGcp struct {
	Config         *stacks.ConfigurationOptions
	AuthOptions    *stacks.AuthenticationOptions
	GcpConfig      *stacks.GCPConfiguration

	ComputeService *compute.Service
}

func (s *StackGcp) GetConfigurationOptions() stacks.ConfigurationOptions {
	return *s.Config
}

func (s *StackGcp) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return *s.AuthOptions
}

// Build Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.GCPConfiguration, cfg stacks.ConfigurationOptions) (*StackGcp, error) {
	stack := &StackGcp{
		Config:        &cfg,
		AuthOptions:   &auth,
		GcpConfig:     &localCfg,
	}

	d1, err := json.MarshalIndent(localCfg, "", "  ")
	if err != nil {
		return &StackGcp{}, err
	}

	cred, err := google.CredentialsFromJSON(context.Background(), d1, iam.CloudPlatformScope)
	if err != nil {
		return &StackGcp{}, err
	}

	stack.ComputeService, err = compute.NewService(context.Background(), option.WithTokenSource(cred.TokenSource))
	if err != nil {
		return &StackGcp{}, err
	}

	return stack, nil
}
