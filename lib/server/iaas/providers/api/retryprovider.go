package api

import (
	"net"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// RetryProvider ...
type RetryProvider WrappedProvider

func (w RetryProvider) CreateVIP(first string, second string) (res *abstract.VirtualIP, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.CreateVIP(first, second)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

func (w RetryProvider) AddPublicIPToVIP(res *abstract.VirtualIP) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.AddPublicIPToVIP(res)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

func (w RetryProvider) BindHostToVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.BindHostToVIP(vip, hostID)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

func (w RetryProvider) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.UnbindHostFromVIP(vip, hostID)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

func (w RetryProvider) DeleteVIP(vip *abstract.VirtualIP) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.DeleteVIP(vip)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

func (w RetryProvider) GetCapabilities() providers.Capabilities {
	return w.InnerProvider.GetCapabilities()
}

func (w RetryProvider) GetTenantParameters() map[string]interface{} {
	return w.InnerProvider.GetTenantParameters()
}

// Provider specific functions

func (w RetryProvider) Build(something map[string]interface{}) (p Provider, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			p, xerr = w.InnerProvider.Build(something)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return p, retryErr
	}

	return p, xerr
}

func (w RetryProvider) ListImages(all bool) (res []abstract.Image, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ListImages(all)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

func (w RetryProvider) ListTemplates(all bool) (res []abstract.HostTemplate, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ListTemplates(all)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

func (w RetryProvider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	return w.InnerProvider.GetAuthenticationOptions()
}

func (w RetryProvider) GetConfigurationOptions() (providers.Config, fail.Error) {
	return w.InnerProvider.GetConfigurationOptions()
}

func (w RetryProvider) GetName() string {
	return w.InnerProvider.GetName()
}

// Stack specific functions

// NewRetryProvider ...
func NewRetryProvider(InnerProvider Provider, name string) *RetryProvider {
	return &RetryProvider{InnerProvider: InnerProvider, Name: name}
}

// ListAvailabilityZones ...
func (w RetryProvider) ListAvailabilityZones() (res map[string]bool, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ListAvailabilityZones()
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// ListRegions ...
func (w RetryProvider) ListRegions() (res []string, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ListRegions()
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// GetImage ...
func (w RetryProvider) GetImage(id string) (res *abstract.Image, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.GetImage(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// GetTemplate ...
func (w RetryProvider) GetTemplate(id string) (res *abstract.HostTemplate, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.GetTemplate(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// CreateKeyPair ...
func (w RetryProvider) CreateKeyPair(name string) (kp *abstract.KeyPair, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			kp, xerr = w.InnerProvider.CreateKeyPair(name)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return kp, retryErr
	}

	return kp, xerr
}

// GetKeyPair ...
func (w RetryProvider) GetKeyPair(id string) (kp *abstract.KeyPair, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			kp, xerr = w.InnerProvider.GetKeyPair(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return kp, retryErr
	}

	return kp, xerr
}

// ListKeyPairs ...
func (w RetryProvider) ListKeyPairs() (res []abstract.KeyPair, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ListKeyPairs()
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// DeleteKeyPair ...
func (w RetryProvider) DeleteKeyPair(id string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.DeleteKeyPair(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

// CreateNetwork ...
func (w RetryProvider) CreateNetwork(req abstract.NetworkRequest) (res *abstract.Network, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.CreateNetwork(req)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// GetNetwork ...
func (w RetryProvider) GetNetwork(id string) (res *abstract.Network, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.GetNetwork(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// GetNetworkByName ...
func (w RetryProvider) GetNetworkByName(name string) (res *abstract.Network, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.GetNetworkByName(name)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// ListNetworks ...
func (w RetryProvider) ListNetworks() (res []*abstract.Network, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ListNetworks()
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// DeleteNetwork ...
func (w RetryProvider) DeleteNetwork(id string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.DeleteNetwork(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

// CreateGateway ...
func (w RetryProvider) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (res *abstract.Host, data *userdata.Content, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, data, xerr = w.InnerProvider.CreateGateway(req, sizing)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, data, retryErr
	}

	return res, data, xerr
}

// DeleteGateway ...
func (w RetryProvider) DeleteGateway(networkID string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.DeleteGateway(networkID)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

// CreateHost ...
func (w RetryProvider) CreateHost(request abstract.HostRequest) (res *abstract.Host, data *userdata.Content, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, data, xerr = w.InnerProvider.CreateHost(request)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, data, retryErr
	}

	return res, data, xerr
}

// InspectHost ...
func (w RetryProvider) InspectHost(something interface{}) (res *abstract.Host, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.InspectHost(something)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// GetHostByName ...
func (w RetryProvider) GetHostByName(name string) (res *abstract.Host, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.GetHostByName(name)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// GetHostByID ...
func (w RetryProvider) GetHostByID(name string) (res *abstract.Host, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.GetHostByID(name)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// GetHostState ...
func (w RetryProvider) GetHostState(something interface{}) (res hoststate.Enum, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.GetHostState(something)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// ListHosts ...
func (w RetryProvider) ListHosts() (res []*abstract.Host, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ListHosts()
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// DeleteHost ...
func (w RetryProvider) DeleteHost(id string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.DeleteHost(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

// StopHost ...
func (w RetryProvider) StopHost(id string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.StopHost(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

// StartHost ...
func (w RetryProvider) StartHost(id string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.StartHost(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

// RebootHost ...
func (w RetryProvider) RebootHost(id string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.RebootHost(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

// ResizeHost ...
func (w RetryProvider) ResizeHost(id string, request abstract.SizingRequirements) (res *abstract.Host, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ResizeHost(id, request)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// CreateVolume ...
func (w RetryProvider) CreateVolume(request abstract.VolumeRequest) (res *abstract.Volume, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.CreateVolume(request)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// GetVolume ...
func (w RetryProvider) GetVolume(id string) (res *abstract.Volume, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.GetVolume(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// ListVolumes ...
func (w RetryProvider) ListVolumes() (res []abstract.Volume, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ListVolumes()
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// DeleteVolume ...
func (w RetryProvider) DeleteVolume(id string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.DeleteVolume(id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}

// CreateVolumeAttachment ...
func (w RetryProvider) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (res string, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.CreateVolumeAttachment(request)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// GetVolumeAttachment ...
func (w RetryProvider) GetVolumeAttachment(serverID, id string) (res *abstract.VolumeAttachment, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.GetVolumeAttachment(serverID, id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// ListVolumeAttachments ...
func (w RetryProvider) ListVolumeAttachments(serverID string) (res []abstract.VolumeAttachment, xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, xerr = w.InnerProvider.ListVolumeAttachments(serverID)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return res, retryErr
	}

	return res, xerr
}

// DeleteVolumeAttachment ...
func (w RetryProvider) DeleteVolumeAttachment(serverID, id string) (xerr fail.Error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			xerr = w.InnerProvider.DeleteVolumeAttachment(serverID, id)
			if xerr != nil {
				switch xerr.(type) {
				case fail.ErrTimeout:
					return xerr
				case *net.DNSError:
					return xerr
				case fail.ErrInvalidRequest:
					return xerr
				default:
					return nil
				}
			}
			return nil
		},
		0,
		temporal.GetContextTimeout(),
	)
	if retryErr != nil {
		return retryErr
	}

	return xerr
}
