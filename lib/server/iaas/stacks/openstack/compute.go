/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package openstack

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/gophercloud/gophercloud/openstack/identity/v3/regions"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	gc "github.com/gophercloud/gophercloud"
	az "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/availabilityzones"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/startstop"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostProperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/IPVersion"
	converters "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
)

// ListRegions ...
func (s *Stack) ListRegions() ([]string, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("openstack.Client.ListRegions() called"), log.TraceLevel)()

	var results []string

	if s == nil {
		panic("Calling method ListRegions from nil!")
	}

	listOpts := regions.ListOpts{
		ParentRegionID: "RegionOne",
	}

	allPages, err := regions.List(s.ComputeClient, listOpts).AllPages()
	if err != nil {
		return results, err
	}

	allRegions, err := regions.ExtractRegions(allPages)
	if err != nil {
		return results, err
	}

	for _, reg := range allRegions {
		results = append(results, reg.ID)
	}

	return results, nil
}

// ListAvailabilityZones lists the usable AvailabilityZones
func (s *Stack) ListAvailabilityZones() (map[string]bool, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("openstack.Client.ListAvailabilityZones() called"), log.TraceLevel)()

	if s == nil {
		panic("Calling method ListAvailabilityZones from nil!")
	}

	allPages, err := az.List(s.ComputeClient).AllPages()
	if err != nil {
		return nil, err
	}

	content, err := az.ExtractAvailabilityZones(allPages)
	if err != nil {
		return nil, err
	}

	azList := map[string]bool{}
	for _, zone := range content {
		if zone.ZoneState.Available {
			azList[zone.ZoneName] = zone.ZoneState.Available
		}
	}

	if len(azList) == 0 {
		log.Warnf("no Availability Zones detected !")
	}

	return azList, nil
}

// ListImages lists available OS images
func (s *Stack) ListImages() ([]resources.Image, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::ListImages() called"), log.TraceLevel)()

	if s == nil {
		panic("Calling stacks.openstack::ListImage from nil pointer!")
	}

	opts := images.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := images.List(s.ComputeClient, opts)

	var imgList []resources.Image

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		imageList, err := images.ExtractImages(page)
		if err != nil {
			log.Debugf("Error listing images: %+v", err)
			return false, errors.Wrap(err, fmt.Sprintf("Error listing images"))
		}

		for _, img := range imageList {
			imgList = append(imgList, resources.Image{ID: img.ID, Name: img.Name})

		}
		return true, nil
	})
	if (len(imgList) == 0) || (err != nil) {
		if err != nil {
			log.Debugf("Error listing images: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing images: %s", ProviderErrorToString(err)))
		}
		// log.Debugf("Image list empty !")
	}
	return imgList, nil
}

// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (*resources.Image, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::GetImage(%s) called", id), log.TraceLevel)()

	if s == nil {
		panic("Calling method GetImage from nil!")
	}

	img, err := images.Get(s.ComputeClient, id).Extract()
	if err != nil {
		log.Debugf("Error getting image: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting image: %s", ProviderErrorToString(err)))
	}
	return &resources.Image{ID: img.ID, Name: img.Name}, nil
}

// GetTemplate returns the Template referenced by id
func (s *Stack) GetTemplate(id string) (*resources.HostTemplate, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::GetTemplate(%s) called", id), log.TraceLevel)()

	if s == nil {
		panic("Calling method GetTemplate from nil!")
	}

	// Try 10 seconds to get template
	var flv *flavors.Flavor
	err := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			var err error
			flv, err = flavors.Get(s.ComputeClient, id).Extract()
			return err
		},
		2*utils.GetDefaultDelay(),
	)
	if err != nil {
		log.Debugf("Error getting template: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("error getting template: %s", ProviderErrorToString(err)))
	}
	return &resources.HostTemplate{
		Cores:    flv.VCPUs,
		RAMSize:  float32(flv.RAM) / 1000.0,
		DiskSize: flv.Disk,
		ID:       flv.ID,
		Name:     flv.Name,
	}, nil
}

// ListTemplates lists available Host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (s *Stack) ListTemplates() ([]resources.HostTemplate, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::ListTemplates() called"), log.TraceLevel)()

	if s == nil {
		panic("Calling method ListTemplates from nil!")
	}

	opts := flavors.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := flavors.ListDetail(s.ComputeClient, opts)

	var flvList []resources.HostTemplate

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		flavorList, err := flavors.ExtractFlavors(page)
		if err != nil {
			return false, err
		}

		for _, flv := range flavorList {

			flvList = append(flvList, resources.HostTemplate{
				Cores:    flv.VCPUs,
				RAMSize:  float32(flv.RAM) / 1000.0,
				DiskSize: flv.Disk,
				ID:       flv.ID,
				Name:     flv.Name,
			})

		}
		return true, nil
	})
	if (len(flvList) == 0) || (err != nil) {
		if err != nil {
			log.Debugf("Error listing templates: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing templates"))
		}
		// log.Debugf("Template list empty !")
	}
	return flvList, nil
}

// CreateKeyPair creates and import a key pair
func (s *Stack) CreateKeyPair(name string) (*resources.KeyPair, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::CreateKeyPair(%s) called", name), log.TraceLevel)()

	if s == nil {
		panic("Calling method CreateKeyPair from nil!")
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey
	pub, _ := ssh.NewPublicKey(&publicKey)
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	pubKey := string(pubBytes)

	priBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	priKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: priBytes,
		},
	)
	priKey := string(priKeyPem)
	return &resources.KeyPair{
		ID:         name,
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: priKey,
	}, nil
}

// GetKeyPair returns the key pair identified by id
func (s *Stack) GetKeyPair(id string) (*resources.KeyPair, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::GetKeyPair(%s) called", id), log.TraceLevel)()

	if s == nil {
		panic("Calling method GetKeyPair from nil!")
	}

	kp, err := keypairs.Get(s.ComputeClient, id).Extract()
	if err != nil {
		log.Debugf("Error getting keypair: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting keypair"))
	}
	return &resources.KeyPair{
		ID:         kp.Name,
		Name:       kp.Name,
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
	}, nil
}

// ListKeyPairs lists available key pairs
// Returned list can be empty
func (s *Stack) ListKeyPairs() ([]resources.KeyPair, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::ListKeyPairs() called"), log.TraceLevel)()

	if s == nil {
		panic("Calling method ListKeyPairs from nil!")
	}

	// Retrieve a pager (i.e. a paginated collection)
	pager := keypairs.List(s.ComputeClient)

	var kpList []resources.KeyPair

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		keyList, err := keypairs.ExtractKeyPairs(page)
		if err != nil {
			return false, err
		}

		for _, kp := range keyList {
			kpList = append(kpList, resources.KeyPair{
				ID:         kp.Name,
				Name:       kp.Name,
				PublicKey:  kp.PublicKey,
				PrivateKey: kp.PrivateKey,
			})
		}
		return true, nil
	})
	if (len(kpList) == 0) || (err != nil) {
		if err != nil {
			log.Debugf("Error listing keypairs: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing keypairs"))
		}
	}
	return kpList, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (s *Stack) DeleteKeyPair(id string) error {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::DeleteKeyPair(%s) called", id), log.TraceLevel)()

	if s == nil {
		panic("Calling method DeleteKeyPair from nil!")
	}

	err := keypairs.Delete(s.ComputeClient, id).ExtractErr()
	if err != nil {
		log.Debugf("Error deleting keypair: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting key pair: %s", ProviderErrorToString(err)))
	}
	return nil
}

// toHostSize converts flavor attributes returned by OpenStack driver into mdel.Host
func (s *Stack) toHostSize(flavor map[string]interface{}) *propsv1.HostSize {
	if s == nil {
		panic("Calling method toHost from nil!")
	}

	hostSize := propsv1.NewHostSize()
	if i, ok := flavor["id"]; ok {
		fid := i.(string)
		tpl, err := s.GetTemplate(fid)
		if err == nil {
			hostSize.Cores = tpl.Cores
			hostSize.DiskSize = tpl.DiskSize
			hostSize.RAMSize = tpl.RAMSize
		}
	} else if _, ok := flavor["vcpus"]; ok {
		hostSize.Cores = flavor["vcpus"].(int)
		hostSize.DiskSize = flavor["disk"].(int)
		hostSize.RAMSize = flavor["ram"].(float32) / 1000.0
	}
	return hostSize
}

// toHostState converts host status returned by OpenStack driver into HostState enum
func toHostState(status string) HostState.Enum {
	switch strings.ToLower(status) {
	case "build", "building":
		return HostState.STARTING
	case "active":
		return HostState.STARTED
	case "rescued":
		return HostState.STOPPING
	case "stopped", "shutoff":
		return HostState.STOPPED
	default:
		return HostState.ERROR
	}
}

// InspectHost updates the data inside host with the data from provider
func (s *Stack) InspectHost(hostParam interface{}) (*resources.Host, error) {
	if s == nil {
		panic("Calling openstack.Stack::InspectHost from nil pointer!")
	}

	var host *resources.Host
	switch hostParam.(type) {
	case string:
		host := resources.NewHost()
		host.ID = hostParam.(string)
	case *resources.Host:
		host = hostParam.(*resources.Host)
	default:
		panic("openstack.Stack::InspectHost(): parameter 'hostParam' must be a string or a *resources.Host!")
	}
	if host == nil {
		panic("openstack.Stack::InspectHost(): parameter 'hostParam' must be a string or a *resources.Host!")
	}
	hostRef := host.Name
	if hostRef == "" {
		hostRef = host.ID
	}
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::InspectHost(%s) called", hostRef), log.TraceLevel)()

	server, err := s.queryServer(host.ID)
	if err != nil {
		return nil, err
	}
	err = s.complementHost(host, server)
	if err != nil {
		return nil, err
	}

	if !host.OK() {
		log.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(host))
	}

	return host, nil
}

func (s *Stack) queryServer(id string) (*servers.Server, error) {
	var (
		server   *servers.Server
		err      error
		notFound bool
	)

	timeout := 2 * utils.GetBigDelay()
	retryErr := retry.WhileUnsuccessful(
		func() error {
			server, err = servers.Get(s.ComputeClient, id).Extract()
			if err != nil {
				switch err.(type) {
				case gc.ErrDefault404:
					// If error is "resource not found", we want to return GopherCloud error as-is to be able
					// to behave differently in this special case. To do so, stop the retry
					notFound = true
					return nil
				case gc.ErrDefault500:
					// When the response is "Internal Server Error", retries
					log.Println("received 'Internal Server Error', retrying servers.Get...")
					return err
				}
				// Any other error stops the retry
				err = fmt.Errorf("error getting host '%s': %s", id, ProviderErrorToString(err))
				return nil
			}

			if server == nil {
				err = fmt.Errorf("error getting host, nil response from gophercloud")
				log.Debug(err)
				return err
			}

			lastState := toHostState(server.Status)
			if lastState != HostState.ERROR && lastState != HostState.STARTING {
				if lastState != HostState.STARTED {
					log.Warnf("unexpected: host status of '%s' is '%s'", id, server.Status)
				}
				err = nil
				return nil
			}
			return fmt.Errorf("server not ready yet")
		},
		utils.GetMinDelay(),
		timeout,
	)
	if retryErr != nil {
		if _, ok := err.(retry.ErrTimeout); ok {
			return nil, fmt.Errorf("failed to get host '%s' information after %v: %s", id, timeout, retryErr.Error())
		}
		return nil, retryErr
	}
	if err != nil {
		return nil, err
	}
	if notFound {
		return nil, resources.ResourceNotFoundError("host", id)
	}

	if server == nil {
		return nil, resources.ResourceNotFoundError("host", id)
	}

	return server, nil
}

// interpretAddresses converts adresses returned by the OpenStack driver
// Returns string slice containing the name of the networks, string map of IP addresses
// (indexed on network name), public ipv4 and ipv6 (if they exists)
func (s *Stack) interpretAddresses(
	addresses map[string]interface{},
) ([]string, map[IPVersion.Enum]map[string]string, string, string) {
	var (
		networks    = []string{}
		addrs       = map[IPVersion.Enum]map[string]string{}
		AcccessIPv4 string
		AcccessIPv6 string
	)

	addrs[IPVersion.IPv4] = map[string]string{}
	addrs[IPVersion.IPv6] = map[string]string{}

	for n, obj := range addresses {
		networks = append(networks, n)
		for _, networkAddresses := range obj.([]interface{}) {
			address := networkAddresses.(map[string]interface{})
			version := address["version"].(float64)
			fixedIP := address["addr"].(string)
			if n == s.cfgOpts.ProviderNetwork {
				switch version {
				case 4:
					AcccessIPv4 = fixedIP
				case 6:
					AcccessIPv6 = fixedIP
				}
			} else {
				switch version {
				case 4:
					addrs[IPVersion.IPv4][n] = fixedIP
				case 6:
					addrs[IPVersion.IPv6][n] = fixedIP
				}
			}

		}
	}
	return networks, addrs, AcccessIPv4, AcccessIPv6
}

// complementHost complements Host data with content of server parameter
func (s *Stack) complementHost(host *resources.Host, server *servers.Server) error {
	if s == nil {
		return utils.InvalidInstanceError()
	}

	networks, addresses, ipv4, ipv6 := s.interpretAddresses(server.Addresses)

	// Updates intrinsic data of host if needed
	if host.ID == "" {
		host.ID = server.ID
	}
	if host.Name == "" {
		host.Name = server.Name
	}

	host.LastState = toHostState(server.Status)
	if host.LastState == HostState.ERROR || host.LastState == HostState.STARTING {
		log.Warn("[TRACE] Unexpected host's last state: %v", host.LastState)
	}

	// Updates Host Property propsv1.HostDescription
	err := host.Properties.LockForWrite(HostProperty.DescriptionV1).ThenUse(func(v interface{}) error {
		hpDescriptionV1 := v.(*propsv1.HostDescription)
		hpDescriptionV1.Created = server.Created
		hpDescriptionV1.Updated = server.Updated
		return nil
	})
	if err != nil {
		return err
	}

	// Updates Host Property propsv1.HostSizing
	err = host.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
		hpSizingV1 := v.(*propsv1.HostSizing)
		if hpSizingV1.AllocatedSize == nil {
			hpSizingV1.AllocatedSize = s.toHostSize(server.Flavor)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Updates Host Property propsv1.HostNetwork
	return host.Properties.LockForWrite(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		hostNetworkV1 := v.(*propsv1.HostNetwork)
		if hostNetworkV1.PublicIPv4 == "" {
			hostNetworkV1.PublicIPv4 = ipv4
		}
		if hostNetworkV1.PublicIPv6 == "" {
			hostNetworkV1.PublicIPv6 = ipv6
		}
		// networks contains network names, but HostProperty.NetworkV1.IPxAddresses has to be
		// indexed on network ID. Tries to convert if possible, if we already have correspondance
		// between network ID and network Name in Host definition
		if len(hostNetworkV1.NetworksByID) > 0 {
			ipv4Addresses := map[string]string{}
			ipv6Addresses := map[string]string{}
			for netid, netname := range hostNetworkV1.NetworksByID {
				if ip, ok := addresses[IPVersion.IPv4][netname]; ok {
					ipv4Addresses[netid] = ip
				} else {
					ipv4Addresses[netid] = ""
				}

				if ip, ok := addresses[IPVersion.IPv6][netname]; ok {
					ipv6Addresses[netid] = ip
				} else {
					ipv6Addresses[netid] = ""
				}
			}
			hostNetworkV1.IPv4Addresses = ipv4Addresses
			hostNetworkV1.IPv6Addresses = ipv6Addresses
		} else {
			networksByID := map[string]string{}
			ipv4Addresses := map[string]string{}
			ipv6Addresses := map[string]string{}
			// Parse networks and fill fields
			for _, netname := range networks {
				// Ignore ProviderNetwork
				if s.cfgOpts.ProviderNetwork == netname {
					continue
				}

				net, err := s.GetNetworkByName(netname)
				if err != nil {
					log.Debugf("Failed to get data for network '%s'", netname)
					continue
				}
				networksByID[net.ID] = ""

				if ip, ok := addresses[IPVersion.IPv4][netname]; ok {
					ipv4Addresses[net.ID] = ip
				} else {
					ipv4Addresses[net.ID] = ""
				}

				if ip, ok := addresses[IPVersion.IPv6][netname]; ok {
					ipv6Addresses[net.ID] = ip
				} else {
					ipv6Addresses[net.ID] = ""
				}
			}
			hostNetworkV1.NetworksByID = networksByID
			// IPvxAddresses are here indexed by names... At least we have them...
			hostNetworkV1.IPv4Addresses = ipv4Addresses
			hostNetworkV1.IPv6Addresses = ipv6Addresses
		}

		// Updates network name and relationships if needed
		config := s.GetConfigurationOptions()
		for netid, netname := range hostNetworkV1.NetworksByID {
			if netname == "" {
				net, err := s.GetNetwork(netid)
				if err != nil {
					switch err.(type) {
					case resources.ErrResourceNotFound:
						log.Errorf(err.Error())
					default:
						log.Errorf("failed to get network '%s': %v", netid, err)
					}
					continue
				}
				if net.Name == config.ProviderNetwork {
					continue
				}
				hostNetworkV1.NetworksByID[netid] = net.Name
				hostNetworkV1.NetworksByName[net.Name] = netid
			}
		}

		return nil
	})
}

// GetHostByName returns the host using the name passed as parameter
func (s *Stack) GetHostByName(name string) (*resources.Host, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::GetHostByName(%s) called", name), log.TraceLevel)()

	if s == nil {
		panic("Calling method GetHostByName from nil!")
	}

	if name == "" {
		panic("name is empty!")
	}

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := servers.GetResult{}
	_, r.Err = s.ComputeClient.Get(s.ComputeClient.ServiceURL("servers?name="+name), &r.Body, &gc.RequestOpts{
		OkCodes: []int{200, 203},
	})
	if r.Err != nil {
		return nil, fmt.Errorf("failed to get data of host '%s': %v", name, r.Err)
	}
	serverList, found := r.Body.(map[string]interface{})["servers"].([]interface{})
	if found && len(serverList) > 0 {
		for _, anon := range serverList {
			entry := anon.(map[string]interface{})
			if entry["name"].(string) == name {
				host := resources.NewHost()
				host.ID = entry["id"].(string)
				host.Name = name
				return s.InspectHost(host)
			}
		}
	}
	return nil, resources.ResourceNotFoundError("host", name)
}

// CreateHost creates an host satisfying request
func (s *Stack) CreateHost(request resources.HostRequest) (*resources.Host, *userdata.Content, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::CreateHost(%s) called", request.ResourceName), log.TraceLevel)()

	if s == nil {
		panic("Calling s.CreateHost with s==nil!")
	}

	userData := userdata.NewContent()

	msgFail := "Failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if request.DefaultGateway == nil && !request.PublicIP {
		return nil, userData, resources.ResourceInvalidRequestError("host creation", "can't create a host without public IP or without attached network")
	}

	// The Default Network is the first of the provided list, by convention
	defaultNetwork := request.Networks[0]
	defaultNetworkID := defaultNetwork.ID
	defaultGateway := request.DefaultGateway
	isGateway := (defaultGateway == nil && defaultNetwork.Name != resources.SingleHostNetworkName)
	defaultGatewayID := ""
	// defaultGatewayPrivateIP := ""
	if defaultGateway != nil {
		// err := defaultGateway.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		// 	hostNetworkV1 := v.(*propsv1.HostNetwork)
		// defaultGatewayPrivateIP = hostNetworkV1.IPv4Addresses[defaultNetworkID]
		defaultGatewayID = defaultGateway.ID
		// 	return nil
		// })
		// if err != nil {
		// 	return nil, userData, errors.Wrap(err, "")
		// }
	}

	var nets []servers.Network
	// If floating IPs are not used and host is public
	// then add provider network to host networks
	if !s.cfgOpts.UseFloatingIP && request.PublicIP {
		nets = append(nets, servers.Network{
			UUID: s.ProviderNetworkID,
		})
	}
	// Add private networks
	for _, n := range request.Networks {
		nets = append(nets, servers.Network{
			UUID: n.ID,
		})
	}

	// If no key pair is supplied create one
	if request.KeyPair == nil {
		id, err := uuid.NewV4()
		if err != nil {
			msg := fmt.Sprintf("failed to create host UUID: %+v", err)
			log.Debugf(utils.Capitalize(msg))
			return nil, userData, fmt.Errorf(msg)
		}

		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
		request.KeyPair, err = s.CreateKeyPair(name)
		if err != nil {
			msg := fmt.Sprintf("failed to create host key pair: %+v", err)
			log.Debugf(utils.Capitalize(msg))
			return nil, userData, fmt.Errorf(msg)
		}
	}
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, userData, fmt.Errorf("failed to generate password: %s", err.Error())
		}
		request.Password = password
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	err := userData.Prepare(s.cfgOpts, request, defaultNetwork.CIDR, "")
	if err != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", err)
		log.Debugf(utils.Capitalize(msg))
		return nil, userData, fmt.Errorf(msg)
	}

	// Determine system disk size based on vcpus count
	template, err := s.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, userData, fmt.Errorf("failed to get image: %s", ProviderErrorToString(err))
	}

	// Select useable availability zone, the first one in the list
	azone, err := s.SelectedAvailabilityZone()
	if err != nil {
		return nil, userData, err
	}

	// Sets provider parameters to create host
	userDataPhase1, err := userData.Generate("phase1")
	if err != nil {
		return nil, userData, err
	}
	srvOpts := servers.CreateOpts{
		Name:             request.ResourceName,
		SecurityGroups:   []string{s.SecurityGroup.Name},
		Networks:         nets,
		FlavorRef:        request.TemplateID,
		ImageRef:         request.ImageID,
		UserData:         userDataPhase1,
		AvailabilityZone: azone,
	}

	// --- Initializes resources.Host ---

	host := resources.NewHost()
	host.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition
	host.Password = request.Password

	err = host.Properties.LockForWrite(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		hostNetworkV1 := v.(*propsv1.HostNetwork)
		hostNetworkV1.DefaultNetworkID = defaultNetworkID
		hostNetworkV1.DefaultGatewayID = defaultGatewayID
		hostNetworkV1.DefaultGatewayPrivateIP = request.DefaultRouteIP
		hostNetworkV1.IsGateway = isGateway
		return nil
	})
	if err != nil {
		return nil, userData, err
	}

	// Adds Host property SizingV1
	err = host.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
		hostSizingV1 := v.(*propsv1.HostSizing)
		// Note: from there, no idea what was the RequestedSize; caller will have to complement this information
		hostSizingV1.Template = request.TemplateID
		hostSizingV1.AllocatedSize = converters.ModelHostTemplateToPropertyHostSize(template)
		return nil
	})
	if err != nil {
		return nil, userData, err
	}

	// --- query provider for host creation ---

	log.Debugf("requesting host resource creation...")
	// Retry creation until success, for 10 minutes
	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			server, err := servers.Create(s.ComputeClient, keypairs.CreateOptsExt{
				CreateOptsBuilder: srvOpts,
			}).Extract()
			if err != nil {
				if server != nil {
					servers.Delete(s.ComputeClient, server.ID)
				}
				msg := ProviderErrorToString(err)
				log.Warnf(msg)
				return fmt.Errorf(msg)
			} else {
				creationZone, zoneErr := s.GetAvailabilityZoneOfServer(server.ID)
				if zoneErr != nil {
					log.Tracef("Host successfully created: {%s} with some warnings {%s}", spew.Sdump(server), zoneErr)
				} else {
					log.Tracef("Host successfully created: {%s} in zone {%s}", spew.Sdump(server), creationZone)
					if creationZone != srvOpts.AvailabilityZone {
						if srvOpts.AvailabilityZone != "" {
							log.Warnf("Host created in the WRONG availability zone: requested '%s' and got instead '%s'", srvOpts.AvailabilityZone, creationZone)
						}
					}
				}
			}

			if server == nil {
				return fmt.Errorf("failed to create server")
			}
			host.ID = server.ID

			// Wait that Host is ready, not just that the build is started
			host, err = s.WaitHostReady(host, utils.GetHostTimeout())
			if err != nil {
				servers.Delete(s.ComputeClient, server.ID)
				msg := ProviderErrorToString(err)
				log.Warnf(msg)
				return fmt.Errorf(msg)
			}
			return nil
		},
		utils.GetLongOperationTimeout(),
	)
	if err != nil {
		log.Debugf("Error creating host: timeout: %+v", err)
		return nil, userData, errors.Wrap(err, fmt.Sprintf("Error creating host: timeout"))
	}
	log.Debugf("host resource created.")

	// Starting from here, delete host if exiting with error
	defer func() {
		if err != nil {
			log.Infof("Cleanup, deleting host '%s'", host.Name)
			derr := s.DeleteHost(host.ID)
			if derr != nil {
				log.Warnf("Error deleting host: %v", derr)
			}
		}
	}()

	// if Floating IP are used and public address is requested
	if s.cfgOpts.UseFloatingIP && request.PublicIP {
		// Create the floating IP
		ip, err := floatingips.Create(s.ComputeClient, floatingips.CreateOpts{
			Pool: s.authOpts.FloatingIPPool,
		}).Extract()
		if err != nil {
			log.Debugf("Error creating host: floating ip: %+v", err)
			return nil, userData, errors.Wrap(err, fmt.Sprintf(msgFail, ProviderErrorToString(err)))
		}

		// Starting from here, delete Floating IP if exiting with error
		defer func() {
			if err != nil {
				log.Debugf("Cleanup, deleting floating ip '%s'", ip.ID)
				derr := floatingips.Delete(s.ComputeClient, ip.ID).ExtractErr()
				if derr != nil {
					log.Errorf("Error deleting Floating IP: %v", derr)
				}
			}
		}()

		// Associate floating IP to host
		err = floatingips.AssociateInstance(s.ComputeClient, host.ID, floatingips.AssociateOpts{
			FloatingIP: ip.IP,
		}).ExtractErr()
		if err != nil {
			msg := fmt.Sprintf(msgFail, ProviderErrorToString(err))
			log.Debugf(msg)
			return nil, userData, errors.Wrap(err, msg)
		}

		err = host.Properties.LockForWrite(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
			hostNetworkV1 := v.(*propsv1.HostNetwork)
			if IPVersion.IPv4.Is(ip.IP) {
				hostNetworkV1.PublicIPv4 = ip.IP
			} else if IPVersion.IPv6.Is(ip.IP) {
				hostNetworkV1.PublicIPv6 = ip.IP
			}
			userData.PublicIP = ip.IP
			return nil
		})
		if err != nil {
			return nil, userData, err
		}
	}

	log.Infoln(msgSuccess)
	return host, userData, nil
}

func (s *Stack) GetAvailabilityZoneOfServer(serverID string) (string, error) {
	type ServerWithAZ struct {
		servers.Server
		az.ServerAvailabilityZoneExt
	}
	var allServers []ServerWithAZ
	allPages, err := servers.List(s.ComputeClient, nil).AllPages()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve servers: %s", err)
	}
	err = servers.ExtractServersInto(allPages, &allServers)
	if err != nil {
		return "", fmt.Errorf("unable to extract servers: %s", err)
	}
	for _, server := range allServers {
		if server.ID == serverID {
			return server.AvailabilityZone, nil
		}
	}

	return "", fmt.Errorf("unable to find availability zone information for server [%s]", serverID)
}

// SelectedAvailabilityZone returns the selected availability zone
func (s *Stack) SelectedAvailabilityZone() (string, error) {
	if s.selectedAvailabilityZone == "" {
		s.selectedAvailabilityZone = s.GetAuthenticationOptions().AvailabilityZone
		if s.selectedAvailabilityZone == "" {
			azList, err := s.ListAvailabilityZones()
			if err != nil {
				return "", err
			}
			var azone string
			for azone = range azList {
				break
			}
			s.selectedAvailabilityZone = azone
		}
		log.Debugf("Selected Availability Zone: '%s'", s.selectedAvailabilityZone)
	}
	return s.selectedAvailabilityZone, nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *resources.Host; any other type will panic
func (s *Stack) WaitHostReady(hostParam interface{}, timeout time.Duration) (*resources.Host, error) {
	if s == nil {
		panic("Calling s.WaitHostReady with s==nil!")
	}

	var (
		host *resources.Host
	)
	switch hostParam.(type) {
	case string:
		host = resources.NewHost()
		host.ID = hostParam.(string)
	case *resources.Host:
		host = hostParam.(*resources.Host)
	default:
		panic("hostParam must be a string or a *resources.Host!")
	}

	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::WaitHostReady(%s) called", host.ID), log.TraceLevel)()

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(host)
			if err != nil {
				return err
			}
			host = hostTmp
			if host.LastState != HostState.STARTED {
				return fmt.Errorf("not in ready state (current state: %s)", host.LastState.String())
			}
			return nil
		},
		utils.GetDefaultDelay(),
		timeout,
	)
	if retryErr != nil {
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return host, fmt.Errorf("timeout waiting to get host '%s' information after %v", host.Name, timeout)
		}
		return host, retryErr
	}
	return host, nil
}

// GetHostState returns the current state of host identified by id
// hostParam can be a string or an instance of *resources.Host; any other type will panic
func (s *Stack) GetHostState(hostParam interface{}) (HostState.Enum, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::GetHostState() called"), log.TraceLevel)()

	if s == nil {
		panic("Calling s.GetHostState with s==nil!")
	}

	host, err := s.InspectHost(hostParam)
	if err != nil {
		return HostState.ERROR, err
	}
	return host.LastState, nil
}

// ListHosts lists all hosts
func (s *Stack) ListHosts() ([]*resources.Host, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::ListHosts() called"), log.TraceLevel)()

	if s == nil {
		panic("Calling s.ListHosts with s==nil!")
	}

	pager := servers.List(s.ComputeClient, servers.ListOpts{})
	var hosts []*resources.Host
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}

		for _, srv := range list {
			h := resources.NewHost()
			err := s.complementHost(h, &srv)
			if err != nil {
				return false, err
			}
			hosts = append(hosts, h)
		}
		return true, nil
	})
	if len(hosts) == 0 || err != nil {
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("error listing hosts : %s", ProviderErrorToString(err)))
		}
		log.Warnf("Hosts lists empty !")
	}
	return hosts, nil
}

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to an host
func (s *Stack) getFloatingIP(hostID string) (*floatingips.FloatingIP, error) {
	if s == nil {
		return nil, utils.InvalidInstanceError()
	}

	pager := floatingips.List(s.ComputeClient)
	var fips []floatingips.FloatingIP
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := floatingips.ExtractFloatingIPs(page)
		if err != nil {
			return false, err
		}

		for _, fip := range list {
			if fip.InstanceID == hostID {
				fips = append(fips, fip)
			}
		}
		return true, nil
	})
	if len(fips) == 0 {
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("No floating IP found for host '%s': %s", hostID, ProviderErrorToString(err)))
		}
		return nil, errors.Wrap(err, fmt.Sprintf("No floating IP found for host '%s'", hostID))

	}
	if len(fips) > 1 {
		return nil, errors.Wrap(err, fmt.Sprintf("Configuration error, more than one Floating IP associated to host '%s'", hostID))
	}
	return &fips[0], nil
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(id string) error {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::DeleteHost(%s) called", id), log.TraceLevel)()

	if s == nil {
		panic("Calling s.DeleteHost with s==nil!")
	}

	if s.cfgOpts.UseFloatingIP {
		fip, err := s.getFloatingIP(id)
		if err == nil {
			if fip != nil {
				err = floatingips.DisassociateInstance(s.ComputeClient, id, floatingips.DisassociateOpts{
					FloatingIP: fip.IP,
				}).ExtractErr()
				if err != nil {
					log.Debugf("Error deleting host: dissociate: %+v", err)
					return errors.Wrap(err, fmt.Sprintf("error deleting host '%s' : %s", id, ProviderErrorToString(err)))
				}
				err = floatingips.Delete(s.ComputeClient, fip.ID).ExtractErr()
				if err != nil {
					log.Debugf("Error deleting host: delete floating ip: %+v", err)
					return errors.Wrap(err, fmt.Sprintf("error deleting host '%s' : %s", id, ProviderErrorToString(err)))
				}
			}
		} else {
			return errors.Wrap(err, fmt.Sprintf("error retrieving floating ip for '%s'", id))
		}
	}

	// Try to remove host for 3 minutes
	outerRetryErr := retry.WhileUnsuccessful(
		func() error {
			resourcePresent := true
			// 1st, send delete host order
			err := servers.Delete(s.ComputeClient, id).ExtractErr()
			if err != nil {
				switch err.(type) {
				case gc.ErrDefault404:
					// Resource not found, consider deletion successful
					log.Debugf("Host '%s' not found, deletion considered successful", id)
					return nil
				default:
					return fmt.Errorf("failed to submit host '%s' deletion: %s", id, ProviderErrorToString(err))
				}
			}
			// 2nd, check host status every 5 seconds until check failed.
			// If check succeeds but state is Error, retry the deletion.
			// If check fails and error isn't 'resource not found', retry
			innerRetryErr := retry.WhileUnsuccessfulDelay5Seconds(
				func() error {
					host, err := servers.Get(s.ComputeClient, id).Extract()
					if err == nil {
						if toHostState(host.Status) == HostState.ERROR {
							return nil
						}
						return fmt.Errorf("host '%s' state is '%s'", host.Name, host.Status)
					}
					switch err.(type) {
					case gc.ErrDefault404:
						resourcePresent = false
						return nil
					}
					return err
				},
				utils.GetContextTimeout(),
			)
			if innerRetryErr != nil {
				if _, ok := innerRetryErr.(retry.ErrTimeout); ok {
					// retry deletion...
					return fmt.Errorf("failed to acknowledge host '%s' deletion! %s", id, innerRetryErr.Error())
				}
				return innerRetryErr
			}
			if !resourcePresent {
				log.Debugf("Host '%s' not found, deletion considered successful after a few retries", id)
				return nil
			}
			return fmt.Errorf("host '%s' in state 'ERROR', retrying to delete", id)
		},
		0,
		2*utils.GetContextTimeout(),
	)
	if outerRetryErr != nil {
		log.Debugf("failed to remove host '%s': %s", id, outerRetryErr.Error())
		return errors.Wrap(outerRetryErr, fmt.Sprintf("Error deleting host: retry error"))
	}
	return nil
}

// StopHost stops the host identified by id
func (s *Stack) StopHost(id string) error {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::StopHost(%s) called", id), log.TraceLevel)()

	if s == nil {
		panic("Calling s.StopHost with s==nil!")
	}

	err := startstop.Stop(s.ComputeClient, id).ExtractErr()
	if err != nil {
		log.Debugf("Error stopping host: stopping host: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("error stopping host : %s", ProviderErrorToString(err)))
	}
	return nil
}

// RebootHost reboots unconditionally the host identified by id
func (s *Stack) RebootHost(id string) error {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::Reboot(%s) called", id), log.TraceLevel)()

	if s == nil {
		panic("Calling s.RebootHost with s==nil!")
	}

	// Try first a soft reboot, and if it fails (because host isn't in ACTIVE state), tries a hard reboot
	err := servers.Reboot(s.ComputeClient, id, servers.RebootOpts{Type: servers.SoftReboot}).ExtractErr()
	if err != nil {
		err = servers.Reboot(s.ComputeClient, id, servers.RebootOpts{Type: servers.HardReboot}).ExtractErr()
	}
	if err != nil {
		ftErr := fmt.Errorf("Error rebooting host [%s]: %s", id, ProviderErrorToString(err))
		log.Debug(ftErr)
		return errors.Wrap(err, ftErr.Error())
	}
	return nil
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(id string) error {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::StartHost(%s) called", id), log.TraceLevel)()

	if s == nil {
		panic("Calling s.StartHost with s==nil!")
	}

	err := startstop.Start(s.ComputeClient, id).ExtractErr()
	if err != nil {
		log.Debugf("Error starting host: starting host: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error starting host : %s", ProviderErrorToString(err)))
	}

	return nil
}

// ResizeHost ...
func (s *Stack) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	defer utils.TimerWithLevel(fmt.Sprintf("stacks.openstack::ResizeHost(%s) called", id), log.TraceLevel)()

	if s == nil {
		panic("Calling s.ResizeHost with s==nil!")
	}

	// TODO RESIZE Resize Host HERE
	log.Warn("Trying to resize a Host...")

	// TODO RESIZE Call this
	// servers.Resize()

	return nil, errors.New("Not implemented yet")
}
