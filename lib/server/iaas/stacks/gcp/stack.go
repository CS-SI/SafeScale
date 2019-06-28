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

// Stack ...
type Stack struct {
	Config      *stacks.ConfigurationOptions
	AuthOptions *stacks.AuthenticationOptions
	GcpConfig   *stacks.GCPConfiguration

	ComputeService *compute.Service
}

// GetConfigurationOptions ...
func (s *Stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return *s.Config
}

// GetAuthenticationOptions ...
func (s *Stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return *s.AuthOptions
}

// New Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.GCPConfiguration, cfg stacks.ConfigurationOptions) (*Stack, error) {
	stack := &Stack{
		Config:      &cfg,
		AuthOptions: &auth,
		GcpConfig:   &localCfg,
	}

	d1, err := json.MarshalIndent(localCfg, "", "  ")
	if err != nil {
		return &Stack{}, err
	}

	cred, err := google.CredentialsFromJSON(context.Background(), d1, iam.CloudPlatformScope)
	if err != nil {
		return &Stack{}, err
	}

	stack.ComputeService, err = compute.NewService(context.Background(), option.WithTokenSource(cred.TokenSource))
	if err != nil {
		return &Stack{}, err
	}

	return stack, nil
}
