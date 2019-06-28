package api

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/sirupsen/logrus"
)

// LogErrorsStack ...
type LogErrorsStack WrappedStack

// NewLogErrorsStack ...
func NewLogErrorsStack(innerStack Stack, name string) *LogErrorsStack {
	return &LogErrorsStack{InnerStack: innerStack, Name: name}
}

// ListAvailabilityZones ...
func (w LogErrorsStack) ListAvailabilityZones() (zones map[string]bool, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListAvailabilityZones()
}

// ListRegions ...
func (w LogErrorsStack) ListRegions() (regions []string, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListRegions()
}

// // ListImages ...
// func (w LogErrorsStack) ListImages() (images []resources.Image, err error) {
// 	defer func() {
// 		if err != nil {
// 			logrus.Tracef("Intercepted error: %v", err)
// 		}
// 	}()
// 	return w.InnerStack.ListImages()
// }

// GetImage ...
func (w LogErrorsStack) GetImage(id string) (image *resources.Image, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetImage(id)
}

// GetTemplate ...
func (w LogErrorsStack) GetTemplate(id string) (hostTemplate *resources.HostTemplate, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetTemplate(id)
}

// // ListTemplates ...
// func (w LogErrorsStack) ListTemplates() (hostTemaplates []resources.HostTemplate, err error) {
// 	defer func() {
// 		if err != nil {
// 			logrus.Tracef("Intercepted error: %v", err)
// 		}
// 	}()
// 	hostTemplates, err := w.InnerStack.ListTemplates()
// 	return hostTemplates, err
// }

// CreateKeyPair ...
func (w LogErrorsStack) CreateKeyPair(name string) (keyPair *resources.KeyPair, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateKeyPair(name)
}

// GetKeyPair ...
func (w LogErrorsStack) GetKeyPair(id string) (keyPair *resources.KeyPair, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetKeyPair(id)
}

// ListKeyPairs ...
func (w LogErrorsStack) ListKeyPairs() (keyPairs []resources.KeyPair, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListKeyPairs()
}

// DeleteKeyPair ...
func (w LogErrorsStack) DeleteKeyPair(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w LogErrorsStack) CreateNetwork(req resources.NetworkRequest) (network *resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateNetwork(req)
}

// GetNetwork ...
func (w LogErrorsStack) GetNetwork(id string) (network *resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetNetwork(id)
}

// GetNetworkByName ...
func (w LogErrorsStack) GetNetworkByName(name string) (network *resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetNetworkByName(name)
}

// ListNetworks ...
func (w LogErrorsStack) ListNetworks() (networks []*resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListNetworks()
}

// DeleteNetwork ...
func (w LogErrorsStack) DeleteNetwork(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteNetwork(id)
}

// CreateGateway ...
func (w LogErrorsStack) CreateGateway(req resources.GatewayRequest) (host *resources.Host, content *userdata.Content, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateGateway(req)
}

// DeleteGateway ...
func (w LogErrorsStack) DeleteGateway(networkID string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteGateway(networkID)
}

// CreateHost ...
func (w LogErrorsStack) CreateHost(request resources.HostRequest) (host *resources.Host, content *userdata.Content, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateHost(request)
}

// InspectHost ...
func (w LogErrorsStack) InspectHost(something interface{}) (host *resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.InspectHost(something)
}

// GetHostByName ...
func (w LogErrorsStack) GetHostByName(name string) (host *resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetHostByName(name)
}

// GetHostState ...
func (w LogErrorsStack) GetHostState(something interface{}) (hostStatus HostState.Enum, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetHostState(something)
}

// ListHosts ...
func (w LogErrorsStack) ListHosts() (hosts []*resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListHosts()
}

// DeleteHost ...
func (w LogErrorsStack) DeleteHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteHost(id)
}

// StopHost ...
func (w LogErrorsStack) StopHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.StopHost(id)
}

// StartHost ...
func (w LogErrorsStack) StartHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.StartHost(id)
}

// RebootHost ...
func (w LogErrorsStack) RebootHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.RebootHost(id)
}

// ResizeHost ...
func (w LogErrorsStack) ResizeHost(id string, request resources.SizingRequirements) (host *resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ResizeHost(id, request)
}

// CreateVolume ...
func (w LogErrorsStack) CreateVolume(request resources.VolumeRequest) (volume *resources.Volume, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateVolume(request)
}

// GetVolume ...
func (w LogErrorsStack) GetVolume(id string) (volume *resources.Volume, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetVolume(id)
}

// ListVolumes ...
func (w LogErrorsStack) ListVolumes() (volumes []resources.Volume, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListVolumes()
}

// DeleteVolume ...
func (w LogErrorsStack) DeleteVolume(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w LogErrorsStack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (attachmentId string, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w LogErrorsStack) GetVolumeAttachment(serverID, id string) (attachment *resources.VolumeAttachment, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments ...
func (w LogErrorsStack) ListVolumeAttachments(serverID string) (attachment []resources.VolumeAttachment, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment ...
func (w LogErrorsStack) DeleteVolumeAttachment(serverID, id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteVolumeAttachment(serverID, id)
}

// // GetConfigurationOptions ...
// func (w LogErrorsStack) GetConfigurationOptions() stacks.ConfigurationOptions {
// 	return w.InnerStack.GetConfigurationOptions()
// }

// // GetAuthenticationOptions ...
// func (w LogErrorsStack) GetAuthenticationOptions() stacks.AuthenticationOptions {
// 	return w.InnerStack.GetAuthenticationOptions()
// }
