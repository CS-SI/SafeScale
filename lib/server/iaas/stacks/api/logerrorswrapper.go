package api

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/sirupsen/logrus"
)

type LogErrorsStack WrappedStack

func NewLogErrorsStack(innerStack Stack, name string) *LogErrorsStack {
	return &LogErrorsStack{InnerStack: innerStack, Name: name}
}

func (w LogErrorsStack) ListAvailabilityZones(all bool) (zones map[string]bool, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListAvailabilityZones(all)
}

func (w LogErrorsStack) ListRegions() (regions []string, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListRegions()
}

func (w LogErrorsStack) ListImages(all bool) (images []resources.Image, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListImages(all)
}

func (w LogErrorsStack) GetImage(id string) (image *resources.Image, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetImage(id)
}

func (w LogErrorsStack) GetTemplate(id string) (hostTemplate *resources.HostTemplate, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetTemplate(id)
}

func (w LogErrorsStack) ListTemplates(all bool) (hostTemaplates []resources.HostTemplate, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	hostTemplates, err := w.InnerStack.ListTemplates(all)
	return hostTemplates, err
}

func (w LogErrorsStack) CreateKeyPair(name string) (keyPair *resources.KeyPair, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateKeyPair(name)
}

func (w LogErrorsStack) GetKeyPair(id string) (keyPair *resources.KeyPair, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetKeyPair(id)
}

func (w LogErrorsStack) ListKeyPairs() (keyPairs []resources.KeyPair, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListKeyPairs()
}

func (w LogErrorsStack) DeleteKeyPair(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteKeyPair(id)
}

func (w LogErrorsStack) CreateNetwork(req resources.NetworkRequest) (network *resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateNetwork(req)
}

func (w LogErrorsStack) GetNetwork(id string) (network *resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetNetwork(id)
}

func (w LogErrorsStack) GetNetworkByName(name string) (network *resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetNetworkByName(name)
}

func (w LogErrorsStack) ListNetworks() (networks []*resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListNetworks()
}

func (w LogErrorsStack) DeleteNetwork(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteNetwork(id)
}

func (w LogErrorsStack) CreateGateway(req resources.GatewayRequest) (host *resources.Host, content *userdata.Content, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateGateway(req)
}

func (w LogErrorsStack) DeleteGateway(networkID string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteGateway(networkID)
}

func (w LogErrorsStack) CreateHost(request resources.HostRequest) (host *resources.Host, content *userdata.Content, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateHost(request)
}

func (w LogErrorsStack) InspectHost(something interface{}) (host *resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.InspectHost(something)
}

func (w LogErrorsStack) GetHostByName(name string) (host *resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetHostByName(name)
}

func (w LogErrorsStack) GetHostState(something interface{}) (hostStatus HostState.Enum, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetHostState(something)
}

func (w LogErrorsStack) ListHosts() (hosts []*resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListHosts()
}

func (w LogErrorsStack) DeleteHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteHost(id)
}

func (w LogErrorsStack) StopHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.StopHost(id)
}

func (w LogErrorsStack) StartHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.StartHost(id)
}

func (w LogErrorsStack) RebootHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.RebootHost(id)
}

func (w LogErrorsStack) ResizeHost(id string, request resources.SizingRequirements) (host *resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ResizeHost(id, request)
}

func (w LogErrorsStack) CreateVolume(request resources.VolumeRequest) (volume *resources.Volume, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateVolume(request)
}

func (w LogErrorsStack) GetVolume(id string) (volume *resources.Volume, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetVolume(id)
}

func (w LogErrorsStack) ListVolumes() (volumes []resources.Volume, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListVolumes()
}

func (w LogErrorsStack) DeleteVolume(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteVolume(id)
}

func (w LogErrorsStack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (attachmentId string, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.CreateVolumeAttachment(request)
}

func (w LogErrorsStack) GetVolumeAttachment(serverID, id string) (attachment *resources.VolumeAttachment, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.GetVolumeAttachment(serverID, id)
}

func (w LogErrorsStack) ListVolumeAttachments(serverID string) (attachment []resources.VolumeAttachment, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.ListVolumeAttachments(serverID)
}

func (w LogErrorsStack) DeleteVolumeAttachment(serverID, id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerStack.DeleteVolumeAttachment(serverID, id)
}

func (w LogErrorsStack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return w.InnerStack.GetConfigurationOptions()
}

func (w LogErrorsStack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return w.InnerStack.GetAuthenticationOptions()
}
