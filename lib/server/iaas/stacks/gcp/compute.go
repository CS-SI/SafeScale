/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gcp

import (
	"fmt"
	"strconv"
	"time"

	"github.com/davecgh/go-spew/spew"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//-------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (s *Stack) ListImages() (images []abstract.Image, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	compuService := s.ComputeService

	images = []abstract.Image{}

	families := []string{"centos-cloud", "debian-cloud", "rhel-cloud", "ubuntu-os-cloud", "suse-cloud", "rhel-sap-cloud", "suse-sap-cloud"}

	for _, family := range families {
		token := ""
		for paginate := true; paginate; {
			resp, err := compuService.Images.List(family).Filter("deprecated.replacement ne .*images.*").PageToken(token).Do()
			if err != nil {
				logrus.Warnf("Can't list public images for project %q", family)
				break
			}

			for _, image := range resp.Items {
				images = append(images, abstract.Image{Name: image.Name, URL: image.SelfLink, ID: strconv.FormatUint(image.Id, 10)})
			}
			token := resp.NextPageToken
			paginate = token != ""
		}
	}

	if len(images) == 0 {
		return images, err
	}

	return images, nil
}

// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (*abstract.Image, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}

	images, err := s.ListImages()
	if err != nil {
		return nil, err
	}

	for _, image := range images {
		if image.ID == id {
			return &image, nil
		}
	}

	return nil, scerr.NotFoundError("image with id '%s' not found", id)
}

//-------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStackGcp ListTemplate method to filter wind and flex instance and add GPU configuration
func (s *Stack) ListTemplates(all bool) (templates []abstract.HostTemplate, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	compuService := s.ComputeService

	templates = []abstract.HostTemplate{}

	token := ""
	for paginate := true; paginate; {
		resp, err := compuService.MachineTypes.List(s.GcpConfig.ProjectID, s.GcpConfig.Zone).PageToken(token).Do()
		if err != nil {
			logrus.Warnf("Can't list public types...: %s", err)
			break
		} else {

			for _, matype := range resp.Items {
				ht := abstract.HostTemplate{
					Cores:   int(matype.GuestCpus),
					RAMSize: float32(matype.MemoryMb / 1024),
					//VPL: GCP Template disk sizing is ridiculous at best, so fill it to 0 and let us size the disk ourselves
					//DiskSize: int(matype.ImageSpaceGb),
					DiskSize: 0,
					ID:       strconv.FormatUint(matype.Id, 10),
					Name:     matype.Name,
				}
				templates = append(templates, ht)
			}
		}
		token := resp.NextPageToken
		paginate = token != ""
	}

	if len(templates) == 0 {
		return templates, err
	}

	return templates, nil
}

//GetTemplate overload OpenStackGcp GetTemplate method to add GPU configuration
func (s *Stack) GetTemplate(id string) (*abstract.HostTemplate, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}

	templates, err := s.ListTemplates(true)
	if err != nil {
		return nil, err
	}

	for _, template := range templates {
		if template.ID == id {
			return &template, nil
		}
	}

	return nil, scerr.NotFoundError("template with id '%s' not found", id)
}

//-------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair creates and import a key pair
func (s *Stack) CreateKeyPair(name string) (*abstract.KeyPair, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	// privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// publicKey := privateKey.PublicKey
	// pub, _ := ssh.NewPublicKey(&publicKey)
	// pubBytes := ssh.MarshalAuthorizedKey(pub)
	// pubKey := string(pubBytes)

	// priBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	// priKeyPem := pem.EncodeToMemory(
	// 	&pem.Block{
	// 		Type:  "RSA PRIVATE KEY",
	// 		Bytes: priBytes,
	// 	},
	// )
	// priKey := string(priKeyPem)
	// return &resources.KeyPair{
	// 	ID:         name,
	// 	Name:       name,
	// 	PublicKey:  pubKey,
	// 	PrivateKey: priKey,
	// }, nil
	return crypt.GenerateRSAKeyPair(name)
}

// GetKeyPair returns the key pair identified by id
func (s *Stack) GetKeyPair(id string) (*abstract.KeyPair, error) {
	return nil, scerr.NotImplementedError("GetKeyPair() not implemented yet") // FIXME Technical debt
}

// ListKeyPairs lists available key pairs
func (s *Stack) ListKeyPairs() ([]abstract.KeyPair, error) {
	return nil, scerr.NotImplementedError("ListKeyPairs() not implemented yet") // FIXME Technical debt
}

// DeleteKeyPair deletes the key pair identified by id
func (s *Stack) DeleteKeyPair(id string) error {
	return scerr.NotImplementedError("DeleteKeyPair() not implemented yet") // FIXME Technical debt
}

// CreateHost creates an host satisfying request
func (s *Stack) CreateHost(request abstract.HostRequest) (host *abstract.HostFull, userData *userdata.Content, err error) {
	if s == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}

	defer scerr.OnPanic(&err)()
	userData = userdata.NewContent()

	resourceName := request.ResourceName
	networks := request.Networks
	hostMustHavePublicIP := request.PublicIP

	if len(networks) == 0 {
		return nil, userData, scerr.InvalidRequestError("the host %s must be on at least one network (even if public)", resourceName)
	}

	// If no key pair is supplied create one
	if request.KeyPair == nil {
		id, err := uuid.NewV4()
		if err != nil {
			msg := fmt.Sprintf("failed to create host UUID: %+s", err.Error())
			logrus.Debugf(strprocess.Capitalize(msg))
			return nil, userData, scerr.NewError(msg)
		}

		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
		request.KeyPair, err = s.CreateKeyPair(name)
		if err != nil {
			msg := fmt.Sprintf("failed to create host key pair: %+s", err.Error())
			logrus.Debugf(strprocess.Capitalize(msg))
			return nil, userData, scerr.NewError(msg)
		}
	}
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, userData, scerr.NewError("failed to generate password: %s", err.Error())
		}
		request.Password = password
	}

	// The Default Network is the first of the provided list, by convention
	defaultNetwork := request.Networks[0]
	defaultNetworkID := defaultNetwork.ID
	defaultGatewayID := request.DefaultGateway.ID
	isGateway := request.DefaultRouteIP == "" && defaultNetwork.Name != abstract.SingleHostNetworkName
	//VPL: moved to ojects.Host.Create()
	// defaultGatewayID := ""
	// defaultGatewayPrivateIP := ""
	// if defaultGateway != nil {
	// err := defaultGateway.properties.Inspect(HostProperty.NetworkV1, func(v interface{}) error {
	// 	hostNetworkV1 := v.(*propertiesv1.HostNetwork)
	// 	defaultGatewayPrivateIP = hostNetworkV1.IPv4Addresses[defaultNetworkID]
	// 	defaultGatewayID = defaultGateway.ID
	// 	return nil
	// })
	// if err != nil {
	// 	return nil, userData, err
	// }
	// }

	// if defaultGateway == nil && !hostMustHavePublicIP {
	if request.DefaultRouteIP == "" && !hostMustHavePublicIP {
		return nil, userData, scerr.InvalidRequestError("the host '%s' must have a gateway or be public", resourceName)
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	err = userData.Prepare(*s.Config, request, defaultNetwork.CIDR, "")
	if err != nil {
		err = scerr.Wrap(err, "failed to prepare user data content")
		logrus.Debugf(strprocess.Capitalize(err.Error()))
		return nil, userData, err
	}

	// Determine system disk size based on vcpus count
	template, err := s.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, userData, scerr.Wrap(err, "failed to get image")
	}
	if request.DiskSize > template.DiskSize {
		template.DiskSize = request.DiskSize
	} else if template.DiskSize == 0 {
		// Determines appropriate disk size
		switch {
		case template.Cores < 16:
			template.DiskSize = 100
		case template.Cores < 32:
			template.DiskSize = 200
		default:
			template.DiskSize = 400
		}
	}

	rim, err := s.GetImage(request.ImageID)
	if err != nil {
		return nil, nil, err
	}

	logrus.Debugf("Selected template: '%s', '%s'", template.ID, template.Name)

	// Select usable availability zone, the first one in the list
	if s.GcpConfig.Zone == "" {
		azList, err := s.ListAvailabilityZones()
		if err != nil {
			return nil, userData, err
		}
		var az string
		for az = range azList {
			break
		}
		s.GcpConfig.Zone = az
		logrus.Debugf("Selected Availability Zone: '%s'", az)
	}

	// Sets provider parameters to create host
	userDataPhase1, err := userData.Generate("phase1")
	if err != nil {
		return nil, userData, err
	}

	// --- Initializes abstract.HostCore ---

	hostCore := abstract.NewHostCore()
	hostCore.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition
	hostCore.Password = request.Password

	//VPL: moved to objects.Host.Create()
	// err = host.properties.Alter(HostProperty.NetworkV1, func(v interface{}) error {
	// 	hostNetworkV1 := v.(*propertiesv1.HostNetwork)
	// 	hostNetworkV1.DefaultNetworkID = defaultNetworkID
	// 	hostNetworkV1.DefaultGatewayID = defaultGatewayID
	// 	hostNetworkV1.DefaultGatewayPrivateIP = defaultGatewayPrivateIP
	// 	hostNetworkV1.IsGateway = isGateway
	// 	return nil
	// })
	// if err != nil {
	// 	return nil, userData, err
	// }

	// // Adds Host property SizingV1
	// err = host.properties.Alter(HostProperty.SizingV1, func(v interface{}) error {
	// 	hostSizingV1 := v.(*propertiesv1.HostSizing)
	// 	// Note: from there, no idea what was the RequestedSize; caller will have to complement this information
	// 	hostSizingV1.Template = request.TemplateID
	// 	hostSizingV1.AllocatedSize = converters.ModelHostTemplateToPropertyHostSize(template)
	// 	return nil
	// })
	// if err != nil {
	// 	return nil, userData, err
	// }

	// --- query provider for host creation ---

	logrus.Debugf("requesting host resource creation...")
	var desistError error

	// Retry creation until success, for 10 minutes
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			server, err := buildGcpMachine(s.ComputeService, s.GcpConfig.ProjectID, request.ResourceName, rim.URL, s.GcpConfig.Region, s.GcpConfig.Zone, s.GcpConfig.NetworkName, defaultNetwork.Name, string(userDataPhase1), isGateway, template)
			if err != nil {
				if server != nil {
					// try deleting server
					killErr := s.DeleteHost(server.ID)
					if killErr != nil {
						switch killErr.(type) {
						case scerr.ErrTimeout:
							logrus.Error("Timeout cleaning up gcp instance")
						default:
							logrus.Errorf("Something else happened to gcp instance: %+v", killErr)
						}
						err = scerr.AddConsequence(err, killErr)
					}
					return err
				}

				if gerr, ok := err.(*googleapi.Error); ok {
					logrus.Warnf("Received GCP errorcode: %d", gerr.Code)

					if !(gerr.Code == 200 || gerr.Code == 429 || gerr.Code == 500 || gerr.Code == 503) {
						desistError = gerr
						return nil
					}
				}

				logrus.Warnf("error creating host: %+v", err)
				return err
			}

			if server == nil {
				return scerr.NewError("failed to create server")
			}

			hostCore.ID = server.ID
			hostCore.Name = server.Name

			// Wait that Host is ready, not just that the build is started
			err = s.WaitHostReady(host, temporal.GetLongOperationTimeout())
			if err != nil {
				killErr := s.DeleteHost(hostCore.ID)
				if killErr != nil {
					switch killErr.(type) {
					case scerr.ErrTimeout:
						logrus.Error("Timeout cleaning up gcp instance")
					default:
						logrus.Errorf("Something else happened to gcp instance: %+v", killErr)
					}
					err = scerr.AddConsequence(err, killErr)
				}
				return err
			}
			return nil
		},
		temporal.GetLongOperationTimeout(),
	)
	if retryErr != nil {
		return nil, userData, retryErr
	}
	if desistError != nil {
		return nil, userData, abstract.ResourceForbiddenError(request.ResourceName, fmt.Sprintf("error creating host: %s", desistError.Error()))
	}
	logrus.Debugf("host resource created.")

	newHost := abstract.NewHostFull()
	newHost.Core = hostCore
	newHost.Sizing = converters.HostTemplateToHostEffectiveSizing(template)
	newHost.Network.IsGateway = isGateway
	newHost.Network.DefaultNetworkID = defaultNetworkID
	newHost.Network.DefaultGatewayID = defaultGatewayID
	newHost.Network.DefaultGatewayPrivateIP = request.DefaultRouteIP

	// Starting from here, delete host if exiting with error
	defer func() {
		if err != nil {
			logrus.Infof("Cleanup, deleting host '%s'", hostCore.Name)
			derr := s.DeleteHost(hostCore.ID)
			if derr != nil {
				switch derr.(type) {
				case scerr.ErrNotFound:
					logrus.Errorf("Cleaning up on failure, failed to delete host '%s', resource not found: '%v'", hostCore.Name, derr)
				case scerr.ErrTimeout:
					logrus.Errorf("Cleaning up on failure, failed to delete host '%s', timeout: '%v'", hostCore.Name, derr)
				default:
					logrus.Errorf("Cleaning up on failure, failed to delete host '%s': '%v'", hostCore.Name, derr)
				}
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	if !newHost.OK() {
		logrus.Warnf("Missing data in host: %s", spew.Sdump(newHost))
	}

	return newHost, userData, nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter.
func (s *Stack) WaitHostReady(hostParam interface{}, timeout time.Duration) (err error) {
	if s == nil {
		return scerr.InvalidInstanceError()
	}

	ahc, hostRef, err := stacks.ValidateHostParam(hostParam)
	if err != nil {
		return err
	}

	tracer := concurrency.NewTracer(nil, true, "(%s)", hostRef).Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostComplete, innerErr := s.InspectHost(ahc)
			if innerErr != nil {
				return innerErr
			}

			if hostComplete.Core.LastState != hoststate.STARTED {
				return scerr.NotAvailableError("not in ready state (current state: %s)", hostComplete.Core.LastState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		timeout,
	)
	if retryErr != nil {
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return abstract.ResourceTimeoutError("host", ahc.Name, timeout)
		}
		return retryErr
	}
	return nil
}

func publicAccess(isPublic bool) []*compute.AccessConfig {
	if isPublic {
		return []*compute.AccessConfig{
			{
				Type: "ONE_TO_ONE_NAT",
				Name: "External NAT",
			},
		}
	}

	return []*compute.AccessConfig{}
}

// buildGcpMachine ...
func buildGcpMachine(
	service *compute.Service,
	projectID string,
	instanceName string,
	imageID string,
	region string,
	zone string,
	network string,
	subnetwork string,
	userdata string,
	isPublic bool,
	template *abstract.HostTemplate,
) (*abstract.HostCore, error) {

	prefix := "https://www.googleapis.com/compute/v1/projects/" + projectID

	imageURL := imageID

	tag := "nat"
	if !isPublic {
		tag = fmt.Sprintf("no-ip-%s", subnetwork)
	}

	instance := &compute.Instance{
		Name:         instanceName,
		Description:  "compute sample instance",
		MachineType:  prefix + "/zones/" + zone + "/machineTypes/" + template.Name,
		CanIpForward: isPublic,
		Tags: &compute.Tags{
			Items: []string{tag},
		},
		Disks: []*compute.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				Type:       "PERSISTENT",
				InitializeParams: &compute.AttachedDiskInitializeParams{
					DiskName:    fmt.Sprintf("%s-disk", instanceName),
					SourceImage: imageURL,
					DiskSizeGb:  int64(template.DiskSize),
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				AccessConfigs: publicAccess(isPublic),
				Network:       prefix + "/global/networks/" + network,
				Subnetwork:    prefix + "/regions/" + region + "/subnetworks/" + subnetwork,
			},
		},
		ServiceAccounts: []*compute.ServiceAccount{
			{
				Email: "default",
				Scopes: []string{
					compute.DevstorageFullControlScope,
					compute.ComputeScope,
				},
			},
		},
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{
				{
					Key:   "startup-script",
					Value: &userdata,
				},
			},
		},
	}

	op, err := service.Instances.Insert(projectID, zone, instance).Do()
	if err != nil {
		return nil, err
	}

	etag := op.Header.Get("Etag")
	oco := OpContext{
		Operation:    op,
		ProjectID:    projectID,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
	if err != nil {
		return nil, err
	}

	inst, err := service.Instances.Get(projectID, zone, instanceName).IfNoneMatch(etag).Do()
	if err != nil {
		return nil, err
	}

	logrus.Tracef("Got compute.Instance, err: %#v, %v", inst, err)

	if googleapi.IsNotModified(err) {
		logrus.Warnf("Instance not modified since insert.")
	}

	hostCore := abstract.NewHostCore()
	hostCore.ID = strconv.FormatUint(inst.Id, 10)
	hostCore.Name = inst.Name

	return hostCore, nil
}

// InspectHost returns the host identified by ref (name or id) or by a *abstract.HostFull containing an id
func (s *Stack) InspectHost(hostParam interface{}) (host *abstract.HostFull, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer scerr.OnPanic(&err)()

	hostComplete := abstract.NewHostFull()

	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, scerr.InvalidParameterError("hostParam", "cannot be empty string")
		}
		hostComplete.Core.ID = hostParam
	case *abstract.HostCore:
		if hostParam == nil {
			return nil, scerr.InvalidParameterError("hostParam", "cannot be nil")
		}
		hostComplete.Core = hostParam
	default:
		return nil, scerr.InvalidParameterError("hostParam", "must be a non-empty string or a *abstract.HostCore")
	}
	hostRef := hostComplete.Core.Name
	if hostRef == "" {
		hostRef = hostComplete.Core.ID
	}

	gcpHost, err := s.ComputeService.Instances.Get(s.GcpConfig.ProjectID, s.GcpConfig.Zone, hostRef).Do()
	if err != nil {
		return nil, err
	}
	_ = &compute.Instance{}
	hostComplete.Core.LastState, err = stateConvert(gcpHost.Status)
	if err != nil {
		return nil, err
	}
	hostComplete.Core.Name = gcpHost.Hostname

	var subnets []IPInSubnet
	for _, nit := range gcpHost.NetworkInterfaces {
		snet := genURL(nit.Subnetwork)
		if !utils.IsEmpty(snet) {
			pubIP := ""
			for _, aco := range nit.AccessConfigs {
				if aco != nil {
					if aco.NatIP != "" {
						pubIP = aco.NatIP
					}
				}
			}

			subnets = append(subnets, IPInSubnet{
				Subnet:   snet,
				IP:       nit.NetworkIP,
				PublicIP: pubIP,
			})
		}
	}

	var resouceNetworks []IPInSubnet
	for _, sn := range subnets {
		region, err := getRegionFromSelfLink(sn.Subnet)
		if err != nil {
			continue
		}
		psg, err := s.ComputeService.Subnetworks.Get(s.GcpConfig.ProjectID, region, getResourceNameFromSelfLink(sn.Subnet)).Do()
		if err != nil {
			continue
		}

		resouceNetworks = append(resouceNetworks, IPInSubnet{
			Subnet:   sn.Subnet,
			Name:     psg.Name,
			ID:       strconv.FormatUint(psg.Id, 10),
			IP:       sn.IP,
			PublicIP: sn.PublicIP,
		})
	}

	ip4bynetid := make(map[string]string)
	netnamebyid := make(map[string]string)
	netidbyname := make(map[string]string)

	ipv4 := ""
	for _, rn := range resouceNetworks {
		ip4bynetid[rn.ID] = rn.IP
		netnamebyid[rn.ID] = rn.Name
		netidbyname[rn.Name] = rn.ID
		if rn.PublicIP != "" {
			ipv4 = rn.PublicIP
		}
	}

	hostComplete.Network.IPv4Addresses = ip4bynetid
	hostComplete.Network.NetworksByID = netnamebyid
	hostComplete.Network.NetworksByName = netidbyname
	hostComplete.Network.PublicIPv4 = ipv4

	hostComplete.Sizing = fromMachineTypeToAllocatedSize(gcpHost.MachineType)

	// if !hostComplete.OK() {
	// 	logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(host))
	// }

	return hostComplete, nil
}

func fromMachineTypeToAllocatedSize(machineType string) *abstract.HostEffectiveSizing {
	hz := abstract.HostEffectiveSizing{}

	// FIXME: Implement mapping

	return &hz
}

func stateConvert(gcpHostStatus string) (hoststate.Enum, error) {
	switch gcpHostStatus {
	case "PROVISIONING":
		return hoststate.STARTING, nil
	case "REPAIRING":
		return hoststate.ERROR, nil
	case "RUNNING":
		return hoststate.STARTED, nil
	case "STAGING":
		return hoststate.STARTING, nil
	case "STOPPED":
		return hoststate.STOPPED, nil
	case "STOPPING":
		return hoststate.STOPPING, nil
	case "SUSPENDED":
		return hoststate.STOPPED, nil
	case "SUSPENDING":
		return hoststate.STOPPING, nil
	case "TERMINATED":
		return hoststate.STOPPED, nil
	default:
		return -1, scerr.NewError("unexpected host status: [%s]", gcpHostStatus)
	}
}

// GetHostByName returns the host identified by ref (name or id)
func (s *Stack) GetHostByName(name string) (*abstract.HostCore, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	hosts, err := s.ListHosts(false)
	if err != nil {
		return nil, err
	}

	for _, host := range hosts {
		if host.Core.Name == name {
			return host.Core, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("host", name)
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(id string) (err error) {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	service := s.ComputeService
	projectID := s.GcpConfig.ProjectID
	zone := s.GcpConfig.Zone
	instanceName := id

	_, err = service.Instances.Get(projectID, zone, instanceName).Do()
	if err != nil {
		return err
	}

	op, err := service.Instances.Delete(projectID, zone, instanceName).Do()
	if err != nil {
		return err
	}

	oco := OpContext{
		Operation:    op,
		ProjectID:    projectID,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostCleanupTimeout())

	waitErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			_, recErr := service.Instances.Get(projectID, zone, instanceName).Do()
			if gerr, ok := recErr.(*googleapi.Error); ok {
				if gerr.Code == 404 {
					return nil
				}
			}
			return scerr.Wrap(recErr, "error waiting for instance '%s' to disappear", instanceName)
		},
		temporal.GetContextTimeout(),
	)

	if waitErr != nil {
		logrus.Error(scerr.Cause(waitErr))
	}

	return err
}

// ResizeHost change the template used by an host
func (s *Stack) ResizeHost(id string, request abstract.HostSizingRequirements) (*abstract.HostFull, error) {
	return nil, scerr.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// ListHosts lists available hosts
func (s *Stack) ListHosts(detailed bool) (abstract.HostList, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	var hostList abstract.HostList
	compuService := s.ComputeService
	token := ""
	for paginate := true; paginate; {
		resp, err := compuService.Instances.List(s.GcpConfig.ProjectID, s.GcpConfig.Zone).PageToken(token).Do()
		if err != nil {
			return hostList, scerr.Wrap(err, "cannot list hosts")
		}
		for _, instance := range resp.Items {
			nhost := abstract.NewHostCore()
			nhost.ID = strconv.FormatUint(instance.Id, 10)
			nhost.Name = instance.Name
			nhost.LastState, _ = stateConvert(instance.Status)

			var hostFull *abstract.HostFull
			if detailed {
				hostFull, err = s.InspectHost(nhost)
				if err != nil {
					return nil, err
				}
			} else {
				hostFull = abstract.NewHostFull()
				hostFull.Core.Replace(nhost)
			}

			// FIXME Populate host, what's missing ?
			hostList = append(hostList, hostFull)
		}
		token := resp.NextPageToken
		paginate = token != ""
	}

	return hostList, nil
}

// StopHost stops the host identified by id
func (s *Stack) StopHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	service := s.ComputeService

	op, err := service.Instances.Stop(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id).Do()
	if err != nil {
		return err
	}

	oco := OpContext{
		Operation:    op,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
	return err
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	service := s.ComputeService

	op, err := service.Instances.Start(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id).Do()
	if err != nil {
		return err
	}

	oco := OpContext{
		Operation:    op,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
	return err
}

// RebootHost reboot the host identified by id
func (s *Stack) RebootHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	service := s.ComputeService

	op, err := service.Instances.Stop(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id).Do()
	if err != nil {
		return err
	}

	oco := OpContext{
		Operation:    op,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
	if err != nil {
		return err
	}

	op, err = service.Instances.Start(s.GcpConfig.ProjectID, s.GcpConfig.Zone, id).Do()
	if err != nil {
		return err
	}

	oco = OpContext{
		Operation:    op,
		ProjectID:    s.GcpConfig.ProjectID,
		Service:      service,
		DesiredState: "DONE",
	}

	err = waitUntilOperationIsSuccessfulOrTimeout(oco, temporal.GetMinDelay(), temporal.GetHostTimeout())
	return err
}

// GetHostState returns the host identified by id
func (s *Stack) GetHostState(hostParam interface{}) (hoststate.Enum, error) {
	if s == nil {
		return hoststate.ERROR, scerr.InvalidInstanceError()
	}

	host, err := s.InspectHost(hostParam)
	if err != nil {
		return hoststate.ERROR, err
	}

	return host.Core.LastState, nil
}

//-------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s *Stack) ListAvailabilityZones() (map[string]bool, error) {
	zones := make(map[string]bool)
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	resp, err := s.ComputeService.Zones.List(s.GcpConfig.ProjectID).Do()
	if err != nil {
		return zones, err
	}
	for _, region := range resp.Items {
		zones[region.Name] = region.Status == "UP"
	}

	return zones, nil
}

// ListRegions ...
func (s *Stack) ListRegions() ([]string, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	var regions []string

	compuService := s.ComputeService

	resp, err := compuService.Regions.List(s.GcpConfig.ProjectID).Do()
	if err != nil {
		return regions, err
	}
	for _, region := range resp.Items {
		regions = append(regions, region.Name)
	}

	return regions, nil
}
