package erbc

import (
	"github.com/CS-SI/SafeScale/iaas/stacks"
)

type StackErbc struct {
	Config         *stacks.ConfigurationOptions
	AuthOptions    *stacks.AuthenticationOptions
}

func (s *StackErbc) GetConfigurationOptions() stacks.ConfigurationOptions {
	panic("implement me")
}

func (s *StackErbc) GetAuthenticationOptions() stacks.AuthenticationOptions {
	panic("implement me")
}

// Build Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.LocalConfiguration, cfg stacks.ConfigurationOptions) (*StackErbc, error) {
	panic("implement me")
}
