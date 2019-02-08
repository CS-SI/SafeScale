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

package openstack

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

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

	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	converters "github.com/CS-SI/SafeScale/providers/model/properties"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/providers/userdata"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/retry"
)

// ListAvailabilityZones lists the usable AvailabilityZones
func (client *Client) ListAvailabilityZones(all bool) (map[string]bool, error) {
	log.Debug(">>> providers.openstack.Client::ListAvailabilityZones()")
	defer log.Debug("<<< providers.openstack::Client.ListAvailabilityZones()")

	if client == nil {
		panic("Calling client.ListAvailabilityZones() with client==nil!")
	}

	allPages, err := az.List(client.Compute).AllPages()
	if err != nil {
		return nil, err
	}

	content, err := az.ExtractAvailabilityZones(allPages)
	if err != nil {
		return nil, err
	}

	azList := map[string]bool{}
	for _, zone := range content {
		if all || zone.ZoneState.Available {
			azList[zone.ZoneName] = zone.ZoneState.Available
		}
	}
	return azList, nil
}

// ListImages lists available OS images
func (client *Client) ListImages(all bool) ([]model.Image, error) {
	log.Debug(">>> providers.openstack.Client::ListImages()")
	defer log.Debug("<<< providers.openstack.Client::ListImages()")

	if client == nil {
		panic("Calling client.ListImages() with client==nil!")
	}

	opts := images.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := images.List(client.Compute, opts)

	var imgList []model.Image

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		imageList, err := images.ExtractImages(page)
		if err != nil {
			log.Debugf("Error listing images: %+v", err)
			return false, errors.Wrap(err, fmt.Sprintf("Error listing images"))
		}

		for _, img := range imageList {
			imgList = append(imgList, model.Image{ID: img.ID, Name: img.Name})

		}
		return true, nil
	})
	if (len(imgList) == 0) || (err != nil) {
		if err != nil {
			log.Debugf("Error listing images: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing images: %s", ProviderErrorToString(err)))
		}
	}
	return imgList, nil
}

// GetImage returns the Image referenced by id
func (client *Client) GetImage(id string) (*model.Image, error) {
	log.Debugf(">>> providers.openstack.Client::GetImage(%s)", id)
	defer log.Debugf("<<< providers.openstack::Client.GetImage(%s)", id)

	if client == nil {
		panic("Calling client.GetImage() with client==nil!")
	}

	img, err := images.Get(client.Compute, id).Extract()
	if err != nil {
		log.Debugf("Error getting image: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting image: %s", ProviderErrorToString(err)))
	}
	return &model.Image{ID: img.ID, Name: img.Name}, nil
}

// GetTemplate returns the Template referenced by id
func (client *Client) GetTemplate(id string) (*model.HostTemplate, error) {
	log.Debugf(">>> providers.openstack.Client::GetTemplate(%s)", id)
	defer log.Debugf("<<< providers.openstack.Client::GetTemplate(%s)", id)

	if client == nil {
		panic("Calling client.GetTemplate() with client==nil!")
	}

	// Try 10 seconds to get template
	var flv *flavors.Flavor
	err := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			var err error
			flv, err = flavors.Get(client.Compute, id).Extract()
			return err
		},
		10*time.Second,
	)
	if err != nil {
		log.Debugf("Error getting template: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("error getting template: %s", ProviderErrorToString(err)))
	}
	return &model.HostTemplate{
		Cores:    flv.VCPUs,
		RAMSize:  float32(flv.RAM) / 1000.0,
		DiskSize: flv.Disk,
		ID:       flv.ID,
		Name:     flv.Name,
	}, nil
}

// ListTemplates lists available Host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (client *Client) ListTemplates(all bool) ([]model.HostTemplate, error) {
	log.Debugf(">>> providers.openstack.Client::ListTemplates() called")
	defer log.Debugf("<<< providers.openstack.Client::ListTemplates() done")

	if client == nil {
		panic("Calling client.ListTemplates() with client==nil!")
	}

	opts := flavors.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := flavors.ListDetail(client.Compute, opts)

	var flvList []model.HostTemplate

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		flavorList, err := flavors.ExtractFlavors(page)
		if err != nil {
			return false, err
		}

		for _, flv := range flavorList {

			flvList = append(flvList, model.HostTemplate{
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
func (client *Client) CreateKeyPair(name string) (*model.KeyPair, error) {
	log.Debugf(">>> providers.openstack.Client::CreateKeyPair(%s)", name)
	defer log.Debugf("<<< providers.openstack.Client::CreateKeyPair(%s)", name)

	if client == nil {
		panic("Calling client.CreateKeyPair() with client==nil!")
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
	return &model.KeyPair{
		ID:         name,
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: priKey,
	}, nil
}

// GetKeyPair returns the key pair identified by id
func (client *Client) GetKeyPair(id string) (*model.KeyPair, error) {
	log.Debugf(">>> providers.openstack.Client.GetKeyPair(%s)", id)
	defer log.Debugf("<<< providers.openstack.Client.GetKeyPair(%s)", id)

	if client == nil {
		panic("Calling client.GetKeyPair() with client==nil!")
	}

	kp, err := keypairs.Get(client.Compute, id).Extract()
	if err != nil {
		log.Debugf("Error getting keypair: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting keypair"))
	}
	return &model.KeyPair{
		ID:         kp.Name,
		Name:       kp.Name,
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
	}, nil
}

// ListKeyPairs lists available key pairs
func (client *Client) ListKeyPairs() ([]model.KeyPair, error) {
	log.Debug(">>> providers.openstack.Client::ListKeyPairs()")
	defer log.Debug("<<< providers.openstack.Client::ListKeyPairs()")

	if client == nil {
		panic("Calling client.ListKeyPairs() with client==nil!")
	}

	// Retrieve a pager (i.e. a paginated collection)
	pager := keypairs.List(client.Compute)

	var kpList []model.KeyPair

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		keyList, err := keypairs.ExtractKeyPairs(page)
		if err != nil {
			return false, err
		}

		for _, kp := range keyList {
			kpList = append(kpList, model.KeyPair{
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
		log.Warnf("No keypairs in the list !")
	}
	return kpList, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (client *Client) DeleteKeyPair(id string) error {
	log.Debugf(">>> providers.openstack.Client.DeleteKeyPair(%s)", id)
	defer log.Debugf("<<< providers.openstack.Client.DeleteKeyPair(%s)", id)

	if client == nil {
		panic("Calling client.DeleteKeyPair() with client==nil!")
	}

	err := keypairs.Delete(client.Compute, id).ExtractErr()
	if err != nil {
		log.Debugf("Error deleting keypair: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting key pair: %s", ProviderErrorToString(err)))
	}
	return nil
}

// toHostSize converts flavor attributes returned by OpenStack driver into model.Host
func (client *Client) toHostSize(flavor map[string]interface{}) *propsv1.HostSize {
	if client == nil {
		panic("Calling client.toHostSize() with client==nil!")
	}

	hostSize := propsv1.NewHostSize()
	if i, ok := flavor["id"]; ok {
		fid := i.(string)
		tpl, err := client.GetTemplate(fid)
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

// GetHost updates the data inside host with the data from provider
func (client *Client) GetHost(hostParam interface{}) (*model.Host, error) {
	log.Debug(">>> providers.openstack.Client::GetHost()")
	defer log.Debug("<<< providers.openstack.Client::GetHost()")

	if client == nil {
		panic("Calling client.GetHost() with client==nil!")
	}

	var (
		host     *model.Host
		server   *servers.Server
		err      error
		notFound bool
	)

	switch hostParam.(type) {
	case string:
		host := model.NewHost()
		host.ID = hostParam.(string)
	case *model.Host:
		host = hostParam.(*model.Host)
	default:
		panic("hostParam must be a string or a *model.Host!")
	}

	const timeout = time.Second * 60

	retryErr := retry.WhileUnsuccessful(
		func() error {
			server, err = servers.Get(client.Compute, host.ID).Extract()
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
				err = fmt.Errorf("Error getting host '%s': %s", host.ID, ProviderErrorToString(err))
				return nil
			}
			if server.Status != "ERROR" && server.Status != "CREATING" {
				host.LastState = toHostState(server.Status)
				return nil
			}
			return fmt.Errorf("server not ready yet")
		},
		timeout,
		1*time.Second,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return nil, fmt.Errorf("failed to get host '%s' information after %v: %s", host.ID, timeout, retryErr.Error())
		}
	}
	if err != nil {
		return nil, err
	}
	if notFound {
		return nil, model.ResourceNotFoundError("host", host.ID)
	}
	err = client.complementHost(host, server)
	if err != nil {
		return nil, err
	}
	return host, nil
}

// interpretAddresses converts adresses returned by the OpenStack driver
// Returns string slice containing the name of the networks, string map of IP addresses
// (indexed on network name), public ipv4 and ipv6 (if they exists)
func (client *Client) interpretAddresses(
	addresses map[string]interface{},
) ([]string, map[IPVersion.Enum]map[string]string, string, string) {
	if client == nil {
		panic("Calling client.interpretAdresses() with client==nil!")
	}

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
			if n == client.Cfg.ProviderNetwork {
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
func (client *Client) complementHost(host *model.Host, server *servers.Server) error {
	if client == nil {
		panic("Calling client.complementHost() with client==nil!")
	}

	networks, addresses, ipv4, ipv6 := client.interpretAddresses(server.Addresses)

	// Updates intrinsic data of host if needed
	if host.ID == "" {
		host.ID = server.ID
	}
	if host.Name == "" {
		host.Name = server.Name
	}

	host.LastState = toHostState(server.Status)

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
			hpSizingV1.AllocatedSize = client.toHostSize(server.Flavor)
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
				if client.Cfg.ProviderNetwork == netname {
					continue
				}

				net, err := client.GetNetworkByName(netname)
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
		config, _ := client.GetCfgOpts()
		providerNetwork, ok := config.Get("ProviderNetwork")
		if !ok {
			providerNetwork = ""
		}
		for netid, netname := range hostNetworkV1.NetworksByID {
			if netname == "" {
				net, err := client.GetNetwork(netid)
				if err != nil {
					switch err.(type) {
					case model.ErrResourceNotFound:
						log.Errorf(err.Error())
					default:
						log.Errorf("failed to get network '%s': %v", netid, err)
					}
					continue
				}
				if net.Name == providerNetwork {
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
func (client *Client) GetHostByName(name string) (*model.Host, error) {
	log.Debugf(">>> providers.openstack.Client::GetHostByName(%s)", name)
	defer log.Debugf("<<< providers.openstack.Client::GetHostByName(%s)", name)

	if client == nil {
		panic("Calling client.GetHostByName() with client==nil!")
	}

	if name == "" {
		panic("name is empty!")
	}

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := servers.GetResult{}
	_, r.Err = client.Compute.Get(client.Compute.ServiceURL("servers?name="+name), &r.Body, &gc.RequestOpts{
		OkCodes: []int{200, 203},
	})
	if r.Err != nil {
		return nil, fmt.Errorf("failed to get data of host '%s': %v", name, r.Err)
	}
	servers, found := r.Body.(map[string]interface{})["servers"].([]interface{})
	if found && len(servers) > 0 {
		for _, anon := range servers {
			entry := anon.(map[string]interface{})
			if entry["name"].(string) == name {
				host := model.NewHost()
				host.ID = entry["id"].(string)
				host.Name = name
				return client.GetHost(host)
			}
		}
	}
	return nil, model.ResourceNotFoundError("host", name)
}

// userData is the structure to apply to userdata.sh template
type userData struct {
	// User is the name of the default user (api.DefaultUser)
	User string
	// Key is the private key used to create the Host
	Key string
	// ConfIF, if set to true, configure all interfaces to DHCP
	ConfIF bool
	// IsGateway, if set to true, activate IP frowarding
	IsGateway bool
	// AddGateway, if set to true, configure default gateway
	AddGateway bool
	// DNSServers contains the list of DNS servers to use
	// Used only if IsGateway is true
	DNSServers []string
	// GatewayIP is the IP of the gateway
	GatewayIP string
	// Password for the user gpac (for troubleshoot use, useable only in console)
	Password string
}

// CreateHost creates an host satisfying request
func (client *Client) CreateHost(request model.HostRequest) (*model.Host, error) {
	log.Debugf(">>> providers.openstack.Client::CreateHost(%s)", request.ResourceName)
	defer log.Debugf("<<< providers.openstack.Client::CreateHost(%s)", request.ResourceName)

	if client == nil {
		panic("Calling client.CreateHost() with client==nil!")
	}

	msgFail := "Failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if request.DefaultGateway == nil && !request.PublicIP {
		return nil, model.ResourceInvalidRequestError("host creation", "can't create a gateway without public IP")
	}

	// The Default Network is the first of the provided list, by convention
	defaultNetwork := request.Networks[0]
	defaultNetworkID := defaultNetwork.ID
	defaultGateway := request.DefaultGateway
	isGateway := (defaultGateway == nil && defaultNetwork.Name != model.SingleHostNetworkName)
	defaultGatewayID := ""
	defaultGatewayPrivateIP := ""
	if defaultGateway != nil {
		err := defaultGateway.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
			hostNetworkV1 := v.(*propsv1.HostNetwork)
			defaultGatewayPrivateIP = hostNetworkV1.IPv4Addresses[defaultNetworkID]
			defaultGatewayID = defaultGateway.ID
			return nil
		})
		if err != nil {
			return nil, errors.Wrap(err, "")
		}
	}

	var nets []servers.Network
	// If floating IPs are not used and host is public
	// then add provider network to host networks
	if !client.Cfg.UseFloatingIP && request.PublicIP {
		nets = append(nets, servers.Network{
			UUID: client.ProviderNetworkID,
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
			return nil, fmt.Errorf(msg)
		}

		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
		request.KeyPair, err = client.CreateKeyPair(name)
		if err != nil {
			msg := fmt.Sprintf("failed to create host key pair: %+v", err)
			log.Debugf(utils.Capitalize(msg))
			return nil, fmt.Errorf(msg)
		}
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData, err := userdata.Prepare(client, request, request.KeyPair, defaultNetwork.CIDR)
	if err != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", err)
		log.Debugf(utils.Capitalize(msg))
		return nil, fmt.Errorf(msg)
	}

	// Determine system disk size based on vcpus count
	template, err := client.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get image: %s", ProviderErrorToString(err))
	}

	// Select useable availability zone, the first one in the list
	azList, err := client.ListAvailabilityZones(false)
	if err != nil {
		return nil, err
	}
	var az string
	for az = range azList {
		break
	}
	log.Debugf("Selected Availability Zone: '%s'", az)

	// Sets provider parameters to create host
	srvOpts := servers.CreateOpts{
		Name:             request.ResourceName,
		SecurityGroups:   []string{client.SecurityGroup.Name},
		Networks:         nets,
		FlavorRef:        request.TemplateID,
		ImageRef:         request.ImageID,
		UserData:         userData,
		AvailabilityZone: az,
	}

	// --- Initializes model.Host ---

	host := model.NewHost()
	host.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition

	err = host.Properties.LockForWrite(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		hostNetworkV1 := v.(*propsv1.HostNetwork)
		hostNetworkV1.DefaultNetworkID = defaultNetworkID
		hostNetworkV1.DefaultGatewayID = defaultGatewayID
		hostNetworkV1.DefaultGatewayPrivateIP = defaultGatewayPrivateIP
		hostNetworkV1.IsGateway = isGateway
		return nil
	})
	if err != nil {
		return nil, err
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
		return nil, err
	}

	// --- query provider for host creation ---

	var hostTmp *model.Host

	log.Debugf("requesting host resource creation...")
	// Retry creation until success, for 10 minutes
	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			server, err := servers.Create(client.Compute, keypairs.CreateOptsExt{
				CreateOptsBuilder: srvOpts,
			}).Extract()
			if err != nil {
				if server != nil {
					servers.Delete(client.Compute, server.ID)
				}
				msg := ProviderErrorToString(err)
				log.Warnf(msg)
				return fmt.Errorf(msg)
			}
			host.ID = server.ID

			// Wait that Host is ready, not just that the build is started
			hostTmp, err = client.WaitHostReady(host, 5*time.Minute)
			if err != nil {
				servers.Delete(client.Compute, server.ID)
				msg := ProviderErrorToString(err)
				log.Warnf(msg)
				return fmt.Errorf(msg)
			}
			return nil
		},
		10*time.Minute,
	)
	if err != nil {
		log.Debugf("Error creating host: timeout: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating host: timeout"))
	}
	if hostTmp == nil {
		return nil, errors.New("unexpected problem creating host")
	}
	log.Debugf("host resource created.")
	host = hostTmp

	// Starting from here, delete host if exiting with error
	defer func() {
		if err != nil {
			log.Infof("Cleanup, deleting host '%s'", host.Name)
			derr := client.DeleteHost(host.ID)
			if derr != nil {
				log.Warnf("Error deleting host: %v", derr)
			}
		}
	}()

	// if Floating IP are used and public address is requested
	if client.Cfg.UseFloatingIP && request.PublicIP {
		// Create the floating IP
		ip, err := floatingips.Create(client.Compute, floatingips.CreateOpts{
			Pool: client.Opts.FloatingIPPool,
		}).Extract()
		if err != nil {
			log.Debugf("Error creating host: floating ip: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf(msgFail, ProviderErrorToString(err)))
		}

		// Starting from here, delete Floating IP if exiting with error
		defer func() {
			if err != nil {
				log.Debugf("Cleanup, deleting floating ip '%s'", ip.ID)
				derr := floatingips.Delete(client.Compute, ip.ID).ExtractErr()
				if derr != nil {
					log.Errorf("Error deleting Floating IP: %v", derr)
				}
			}
		}()

		// Associate floating IP to host
		err = floatingips.AssociateInstance(client.Compute, host.ID, floatingips.AssociateOpts{
			FloatingIP: ip.IP,
		}).ExtractErr()
		if err != nil {
			msg := fmt.Sprintf(msgFail, ProviderErrorToString(err))
			log.Debugf(msg)
			return nil, errors.Wrap(err, msg)
		}

		err = host.Properties.LockForWrite(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
			hostNetworkV1 := v.(*propsv1.HostNetwork)
			if IPVersion.IPv4.Is(ip.IP) {
				hostNetworkV1.PublicIPv4 = ip.IP
			} else if IPVersion.IPv6.Is(ip.IP) {
				hostNetworkV1.PublicIPv6 = ip.IP
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	log.Infoln(msgSuccess)
	return host, nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *model.Host; any other type will panic
func (client *Client) WaitHostReady(hostParam interface{}, timeout time.Duration) (*model.Host, error) {
	if client == nil {
		panic("Calling client.WaitHostReady() with client==nil!")
	}

	var (
		host *model.Host
		err  error
	)
	switch hostParam.(type) {
	case string:
		host = model.NewHost()
		host.ID = hostParam.(string)
	case *model.Host:
		host = hostParam.(*model.Host)
	default:
		panic("hostParam must be a string or a *model.Host!")
	}
	log.Debugf(">>> providers.openstack.Client::WaitHostReady(%s)", host.ID)
	defer log.Debugf("<<< providers.openstack.Client::WaitHostReady(%s)", host.ID)

	retryErr := retry.WhileUnsuccessful(
		func() error {
			host, err = client.GetHost(host)
			if err != nil {
				return err
			}
			if host.LastState != HostState.STARTED {
				return fmt.Errorf("not in ready state (current state: %s)", host.LastState.String())
			}
			return nil
		},
		5*time.Second,
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return nil, fmt.Errorf("timeout waiting to get host '%s' information after %v", host.Name, timeout)
		}
		return nil, retryErr
	}
	return host, nil
}

// GetHostState returns the current state of host identified by id
// hostParam can be a string or an instance of *model.Host; any other type will panic
func (client *Client) GetHostState(hostParam interface{}) (HostState.Enum, error) {
	log.Debug(">>> providers.openstack.Client::GetHostState()")
	defer log.Debug("<<< providers.openstack.Client::GetHostState()")

	if client == nil {
		panic("Calling client.GetHostState() with client==nil!")
	}

	host, err := client.GetHost(hostParam)
	if err != nil {
		return HostState.ERROR, err
	}
	return host.LastState, nil
}

// ListHosts lists all hosts
func (client *Client) ListHosts() ([]*model.Host, error) {
	log.Debug(">>> providers.openstack.Client::ListHosts()")
	defer log.Debug("<<< providers.openstack.Client::ListHosts()")

	if client == nil {
		panic("Calling client.ListHosts() with client==nil!")
	}

	pager := servers.List(client.Compute, servers.ListOpts{})
	var hosts []*model.Host
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}

		for _, srv := range list {
			h := model.NewHost()
			err := client.complementHost(h, &srv)
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
func (client *Client) getFloatingIP(hostID string) (*floatingips.FloatingIP, error) {
	if client == nil {
		panic("Calling client.getFloatingIP() with client==nil!")
	}

	pager := floatingips.List(client.Compute)
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
func (client *Client) DeleteHost(id string) error {
	log.Debugf(">>> providers.openstack.Client::DeleteHost(%s)", id)
	defer log.Debugf("<<< providers.openstack.Client::DeleteHost(%s)", id)

	if client == nil {
		panic("Calling client.DeleteHost() with client==nil!")
	}

	if client.Cfg.UseFloatingIP {
		fip, err := client.getFloatingIP(id)
		if err == nil {
			if fip != nil {
				err = floatingips.DisassociateInstance(client.Compute, id, floatingips.DisassociateOpts{
					FloatingIP: fip.IP,
				}).ExtractErr()
				if err != nil {
					log.Debugf("Error deleting host: dissociate: %+v", err)
					return errors.Wrap(err, fmt.Sprintf("error deleting host '%s' : %s", id, ProviderErrorToString(err)))
				}
				err = floatingips.Delete(client.Compute, fip.ID).ExtractErr()
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
			err := servers.Delete(client.Compute, id).ExtractErr()
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
					host, err := servers.Get(client.Compute, id).Extract()
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
				1*time.Minute,
			)
			if innerRetryErr != nil {
				switch innerRetryErr.(type) {
				case retry.ErrTimeout:
					// retry deletion...
					return fmt.Errorf("failed to acknowledge host '%s' deletion! %s", id, innerRetryErr.Error())
				default:
					return innerRetryErr
				}
			}
			if !resourcePresent {
				log.Debugf("Host '%s' not found, deletion considered successful after a few retries", id)
				return nil
			}
			return fmt.Errorf("host '%s' in state 'ERROR', retrying to delete", id)
		},
		0,
		3*time.Minute,
	)
	if outerRetryErr != nil {
		log.Debugf("failed to remove host '%s': %s", id, outerRetryErr.Error())
		return errors.Wrap(outerRetryErr, fmt.Sprintf("Error deleting host: retry error"))
	}
	return nil
}

// StopHost stops the host identified by id
func (client *Client) StopHost(id string) error {
	log.Debugf(">>> providers.openstack.Client::StopHost(%s)", id)
	defer log.Debugf("<<< providers.openstack.Client::StopHost(%s)", id)

	if client == nil {
		panic("Calling client.StopHost() with client==nil!")
	}

	err := startstop.Stop(client.Compute, id).ExtractErr()
	if err != nil {
		log.Debugf("Error stopping host: stopping host: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("error stopping host : %s", ProviderErrorToString(err)))
	}
	return nil
}

// RebootHost reboots inconditionnaly the host identified by id
func (client *Client) RebootHost(id string) error {
	log.Debugf(">>> providers.openstack.Client::Reboot(%s)", id)
	defer log.Debugf("<<< providers.openstack.Client::Reboot(%s)", id)

	if client == nil {
		panic("Calling client.RebootHost() with client==nil!")
	}

	err := servers.Reboot(client.Compute, id, servers.RebootOpts{Type: "HARD"}).ExtractErr()
	if err != nil {
		ftErr := fmt.Errorf("Error rebooting host [%s]: %s", id, ProviderErrorToString(err))
		log.Debug(ftErr)
		return errors.Wrap(err, ftErr.Error())
	}
	return nil
}

// StartHost starts the host identified by id
func (client *Client) StartHost(id string) error {
	log.Debugf(">>> providers.openstack.Client::StartHost(%s)", id)
	defer log.Debugf("<<< providers.openstack.Client::StartHost(%s)", id)

	if client == nil {
		panic("Calling client.StartHost() with client==nil!")
	}

	err := startstop.Start(client.Compute, id).ExtractErr()
	if err != nil {
		log.Debugf("Error starting host: starting host: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error starting host : %s", ProviderErrorToString(err)))
	}

	return nil
}

// ResizeHost ...
func (client *Client) ResizeHost(id string, request model.SizingRequirements) (*model.Host, error) {
	log.Debugf(">>> providers.openstack.Client::ResizeHost(%s)", id)
	defer log.Debugf("<<< providers.openstack.Client::ResizeHost(%s)", id)

	if client == nil {
		panic("Calling client.ResizeHost() with client==nil!")
	}

	// TODO RESIZE Implement Resize Host HERE
	log.Warn("Trying to resize a Host...")

	// TODO RESIZE Call this
	// servers.Resize()

	return nil, errors.New("not implemented yet !")
}
