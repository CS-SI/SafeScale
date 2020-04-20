package ebrc

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/vmware/go-vcloud-director/govcd"
	"net/url"
)

type StackEbrc struct {
	EbrcService *govcd.VCDClient
	Config      *stacks.ConfigurationOptions
	AuthOptions *stacks.AuthenticationOptions
}

func (s *StackEbrc) GetConfigurationOptions() stacks.ConfigurationOptions {
	return *s.Config
}

func (s *StackEbrc) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return *s.AuthOptions
}

// Build Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.VCloudConfigurationOptions, cfg stacks.ConfigurationOptions) (*StackEbrc, error) {
	stack := &StackEbrc{
		Config:      &cfg,
		AuthOptions: &auth,
	}

	u, err := url.ParseRequestURI(auth.IdentityEndpoint)
	if err != nil {
		return nil, fmt.Errorf("Unable to pass url: %s", err)
	}

	vcdclient := govcd.NewVCDClient(*u, localCfg.Insecure)
	err = vcdclient.Authenticate(auth.Username, auth.Password, auth.ProjectName)
	if err != nil {
		return nil, fmt.Errorf("Unable to authenticate: %s", err)
	}
	stack.EbrcService = vcdclient

	return stack, nil
}
