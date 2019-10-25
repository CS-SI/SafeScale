//+build libvirt

package local

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	libvirt "github.com/libvirt/libvirt-go"
)

type Stack struct {
	LibvirtService *libvirt.Connect
	LibvirtConfig  *stacks.LocalConfiguration
	Config         *stacks.ConfigurationOptions
	AuthOptions    *stacks.AuthenticationOptions
}

func (s Stack) WaitHostReady(hostParam interface{}, timeout time.Duration) (*resources.Host, error) {
	panic("implement me")
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
		return nil, fmt.Errorf("failed to connect to libvirt : %s", err.Error())
	}
	stack.LibvirtService = libvirtConnection

	if stack.LibvirtConfig.LibvirtStorage != "" {
		err := stack.CreatePoolIfUnexistant(stack.LibvirtConfig.LibvirtStorage)
		if err != nil {
			return nil, fmt.Errorf("unable to create StoragePool : %s", err.Error())
		}
	}

	return stack, nil
}
