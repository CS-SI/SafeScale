//+build libvirt

package local

import (
	"time"

	"github.com/libvirt/libvirt-go"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

type Stack struct {
	LibvirtService *libvirt.Connect
	LibvirtConfig  *stacks.LocalConfiguration
	Config         *stacks.ConfigurationOptions
	AuthOptions    *stacks.AuthenticationOptions
}

func (s Stack) WaitHostReady(hostParam interface{}, timeout time.Duration) error {
	return nil, fail.NotImplementedReport("WaitHostReady not implemented yet!") // FIXME: Technical debt
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
		return nil, fail.Wrap(err, "failed to connect to libvirt")
	}
	stack.LibvirtService = libvirtConnection

	if stack.LibvirtConfig.LibvirtStorage != "" {
		err := stack.CreatePoolIfUnexistant(stack.LibvirtConfig.LibvirtStorage)
		if err != nil {
			return nil, fail.Wrap(err, "unable to create StoragePool")
		}
	}

	return stack, nil
}
