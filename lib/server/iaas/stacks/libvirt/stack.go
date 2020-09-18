// +build libvirt

package local

import (
	"fmt"

	"github.com/libvirt/libvirt-go"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

type Stack struct {
	LibvirtService *libvirt.Connect
	LibvirtConfig  *stacks.LocalConfiguration
	Config         *stacks.ConfigurationOptions
	AuthOptions    *stacks.AuthenticationOptions
}

// Build Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.LocalConfiguration, cfg stacks.ConfigurationOptions) (*Stack, error) {
	stack := &Stack{
		Config:        &cfg,
		LibvirtConfig: &localCfg,
		AuthOptions:   &auth,
	}

	libvirtConnection, err := libvirt.NewConnect(stack.LibvirtConfig.URI)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to connect to libvirt : %s", err.Error()), err)
	}
	stack.LibvirtService = libvirtConnection

	if stack.LibvirtConfig.LibvirtStorage != "" {
		err := stack.CreatePoolIfUnexistant(stack.LibvirtConfig.LibvirtStorage)
		if err != nil {
			return nil, scerr.Errorf(fmt.Sprintf("unable to create StoragePool : %s", err.Error()), err)
		}
	}

	return stack, nil
}
