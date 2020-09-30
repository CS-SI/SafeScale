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

func (w RetryProvider) CreateVIP(first string, second string) (res *abstract.VirtualIP, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.CreateVIP(first, second)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

func (w RetryProvider) AddPublicIPToVIP(res *abstract.VirtualIP) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.AddPublicIPToVIP(res)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

func (w RetryProvider) BindHostToVIP(vip *abstract.VirtualIP, hostID string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.BindHostToVIP(vip, hostID)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

func (w RetryProvider) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.UnbindHostFromVIP(vip, hostID)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

func (w RetryProvider) DeleteVIP(vip *abstract.VirtualIP) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.DeleteVIP(vip)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

func (w RetryProvider) GetCapabilities() providers.Capabilities {
	return w.InnerProvider.GetCapabilities()
}

func (w RetryProvider) GetTenantParameters() map[string]interface{} {
	return w.InnerProvider.GetTenantParameters()
}

// Provider specific functions

func (w RetryProvider) Build(something map[string]interface{}) (p Provider, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			p, err = w.InnerProvider.Build(something)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return p, err
}

func (w RetryProvider) ListImages(all bool) (res []abstract.Image, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ListImages(all)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

func (w RetryProvider) ListTemplates(all bool) (res []abstract.HostTemplate, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ListTemplates(all)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

func (w RetryProvider) GetAuthenticationOptions() (providers.Config, error) {
	return w.InnerProvider.GetAuthenticationOptions()
}

func (w RetryProvider) GetConfigurationOptions() (providers.Config, error) {
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
func (w RetryProvider) ListAvailabilityZones() (res map[string]bool, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ListAvailabilityZones()
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// ListRegions ...
func (w RetryProvider) ListRegions() (res []string, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ListRegions()
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// GetImage ...
func (w RetryProvider) GetImage(id string) (res *abstract.Image, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.GetImage(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// GetTemplate ...
func (w RetryProvider) GetTemplate(id string) (res *abstract.HostTemplate, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.GetTemplate(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// CreateKeyPair ...
func (w RetryProvider) CreateKeyPair(name string) (kp *abstract.KeyPair, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			kp, err = w.InnerProvider.CreateKeyPair(name)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return kp, err
}

// GetKeyPair ...
func (w RetryProvider) GetKeyPair(id string) (kp *abstract.KeyPair, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			kp, err = w.InnerProvider.GetKeyPair(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return kp, err
}

// ListKeyPairs ...
func (w RetryProvider) ListKeyPairs() (res []abstract.KeyPair, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ListKeyPairs()
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// DeleteKeyPair ...
func (w RetryProvider) DeleteKeyPair(id string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.DeleteKeyPair(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

// CreateNetwork ...
func (w RetryProvider) CreateNetwork(req abstract.NetworkRequest) (res *abstract.Network, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.CreateNetwork(req)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// GetNetwork ...
func (w RetryProvider) GetNetwork(id string) (res *abstract.Network, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.GetNetwork(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// GetNetworkByName ...
func (w RetryProvider) GetNetworkByName(name string) (res *abstract.Network, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.GetNetworkByName(name)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// ListNetworks ...
func (w RetryProvider) ListNetworks() (res []*abstract.Network, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ListNetworks()
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// DeleteNetwork ...
func (w RetryProvider) DeleteNetwork(id string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.DeleteNetwork(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

// CreateGateway ...
func (w RetryProvider) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (res *abstract.Host, data *userdata.Content, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, data, err = w.InnerProvider.CreateGateway(req, sizing)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, data, err
}

// DeleteGateway ...
func (w RetryProvider) DeleteGateway(networkID string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.DeleteGateway(networkID)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

// CreateHost ...
func (w RetryProvider) CreateHost(request abstract.HostRequest) (res *abstract.Host, data *userdata.Content, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, data, err = w.InnerProvider.CreateHost(request)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, data, err
}

// InspectHost ...
func (w RetryProvider) InspectHost(something interface{}) (res *abstract.Host, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.InspectHost(something)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// GetHostByName ...
func (w RetryProvider) GetHostByName(name string) (res *abstract.Host, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.GetHostByName(name)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// GetHostState ...
func (w RetryProvider) GetHostState(something interface{}) (res hoststate.Enum, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.GetHostState(something)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// ListHosts ...
func (w RetryProvider) ListHosts() (res []*abstract.Host, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ListHosts()
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// DeleteHost ...
func (w RetryProvider) DeleteHost(id string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.DeleteHost(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

// StopHost ...
func (w RetryProvider) StopHost(id string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.StopHost(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

// StartHost ...
func (w RetryProvider) StartHost(id string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.StartHost(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

// RebootHost ...
func (w RetryProvider) RebootHost(id string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.RebootHost(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

// ResizeHost ...
func (w RetryProvider) ResizeHost(id string, request abstract.SizingRequirements) (res *abstract.Host, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ResizeHost(id, request)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// CreateVolume ...
func (w RetryProvider) CreateVolume(request abstract.VolumeRequest) (res *abstract.Volume, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.CreateVolume(request)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// GetVolume ...
func (w RetryProvider) GetVolume(id string) (res *abstract.Volume, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.GetVolume(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// ListVolumes ...
func (w RetryProvider) ListVolumes() (res []abstract.Volume, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ListVolumes()
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// DeleteVolume ...
func (w RetryProvider) DeleteVolume(id string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.DeleteVolume(id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}

// CreateVolumeAttachment ...
func (w RetryProvider) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (res string, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.CreateVolumeAttachment(request)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// GetVolumeAttachment ...
func (w RetryProvider) GetVolumeAttachment(serverID, id string) (res *abstract.VolumeAttachment, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.GetVolumeAttachment(serverID, id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// ListVolumeAttachments ...
func (w RetryProvider) ListVolumeAttachments(serverID string) (res []abstract.VolumeAttachment, err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			res, err = w.InnerProvider.ListVolumeAttachments(serverID)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return res, err
}

// DeleteVolumeAttachment ...
func (w RetryProvider) DeleteVolumeAttachment(serverID, id string) (err error) {
	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = w.InnerProvider.DeleteVolumeAttachment(serverID, id)
			if err != nil {
				switch err.(type) {
				case fail.ErrTimeout:
					return err
				case *net.DNSError:
					return err
				case fail.ErrInvalidRequest:
					return err
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

	return err
}
