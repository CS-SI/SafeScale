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

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/startstop"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/providers/userdata"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/retry"
)

// ListImages lists available OS images
func (client *Client) ListImages(all bool) ([]model.Image, error) {
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
		log.Warnf("Image list empty !")
	}
	return imgList, nil
}

// GetImage returns the Image referenced by id
func (client *Client) GetImage(id string) (*model.Image, error) {
	img, err := images.Get(client.Compute, id).Extract()
	if err != nil {
		log.Debugf("Error getting image: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting image: %s", ProviderErrorToString(err)))
	}
	return &model.Image{ID: img.ID, Name: img.Name}, nil
}

// GetTemplate returns the Template referenced by id
func (client *Client) GetTemplate(id string) (*model.HostTemplate, error) {
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
		HostTemplate: propsv1.HostTemplate{
			HostSize: propsv1.HostSize{
				Cores:    flv.VCPUs,
				RAMSize:  float32(flv.RAM) / 1000.0,
				DiskSize: flv.Disk,
			},
			ID:   flv.ID,
			Name: flv.Name,
		},
	}, nil
}

// ListTemplates lists available Host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (client *Client) ListTemplates(all bool) ([]model.HostTemplate, error) {
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
				HostTemplate: propsv1.HostTemplate{
					HostSize: propsv1.HostSize{
						Cores:    flv.VCPUs,
						RAMSize:  float32(flv.RAM) / 1000.0,
						DiskSize: flv.Disk,
					},
					ID:   flv.ID,
					Name: flv.Name,
				},
			})

		}
		return true, nil
	})
	if (len(flvList) == 0) || (err != nil) {
		if err != nil {
			log.Debugf("Error listing templates: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing templates"))
		}
		log.Warnf("Template list empty !")
	}
	return flvList, nil
}

// CreateKeyPair creates and import a key pair
func (client *Client) CreateKeyPair(name string) (*model.KeyPair, error) {
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
	err := keypairs.Delete(client.Compute, id).ExtractErr()
	if err != nil {
		log.Debugf("Error deleting keypair: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting key pair: %s", ProviderErrorToString(err)))
	}
	return nil
}

// toHostSize converts flavor attributes returned by OpenStack driver into mdel.Host
func (client *Client) toHostSize(flavor map[string]interface{}) propsv1.HostSize {
	if i, ok := flavor["id"]; ok {
		fid := i.(string)
		tpl, err := client.GetTemplate(fid)
		if err == nil {
			return tpl.HostSize
		}
	}
	if _, ok := flavor["vcpus"]; ok {
		return propsv1.HostSize{
			Cores:    flavor["vcpus"].(int),
			DiskSize: flavor["disk"].(int),
			RAMSize:  flavor["ram"].(float32) / 1000.0,
		}
	}
	return propsv1.HostSize{}
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

// UpdateHost updates the data inside host with the data from provider
// TODO: move this method on the model.Host struct
func (client *Client) UpdateHost(host *model.Host) error {
	var (
		server *servers.Server
		err    error
	)

	retryErr := retry.WhileUnsuccessful(
		func() error {
			server, err = servers.Get(client.Compute, host.ID).Extract()
			if err != nil {
				switch err.(type) {
				case gc.ErrDefault404:
					// If error is "resource not found", we want to return GopherCloud error as-is to be able
					// to behave differently in this special case. To do so, stop the retry
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
		10*time.Second,
		1*time.Second,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return fmt.Errorf("failed to get host '%s' information after 10s: %s", host.ID, err.Error())
		}
	}
	if err != nil {
		return err
	}
	err = client.complementHost(host, server)
	if err != nil {
		return err
	}
	return nil
}

// interpretAddresses converts adresses returned by the OpenStack driver
// Returns string slice containing the name of the networks, string map of IP addresses
// (indexed on network name), public ipv4 and ipv6 (if they exists)
func (client *Client) interpretAddresses(
	addresses map[string]interface{},
) ([]string, map[IPVersion.Enum]map[string]string, string, string) {

	var (
		networks    = []string{}
		addrs       = map[IPVersion.Enum]map[string]string{}
		AcccessIPv4 string
		AcccessIPv6 string
	)

	addrs[IPVersion.IPv4] = map[string]string{}
	addrs[IPVersion.IPv4] = map[string]string{}

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
	hpDescriptionV1 := propsv1.BlankHostDescription
	err := host.Properties.Get(HostProperty.DescriptionV1, &hpDescriptionV1)
	if err != nil {
		return err
	}
	hpDescriptionV1.Created = server.Created
	hpDescriptionV1.Updated = server.Updated
	err = host.Properties.Set(HostProperty.DescriptionV1, &hpDescriptionV1)
	if err != nil {
		return err
	}

	// Updates Host Property propsv1.HostSizing
	hpSizingV1 := propsv1.BlankHostSizing
	err = host.Properties.Get(HostProperty.SizingV1, &hpSizingV1)
	if err != nil {
		return err
	}
	hpSizingV1.AllocatedSize = client.toHostSize(server.Flavor)
	err = host.Properties.Set(HostProperty.SizingV1, &hpSizingV1)
	if err != nil {
		return err
	}

	// Updates Host Property propsv1.HostNetwork
	hpNetworkV1 := propsv1.BlankHostNetwork
	err = host.Properties.Get(HostProperty.NetworkV1, &hpNetworkV1)
	if err != nil {
		return err
	}
	if hpNetworkV1.PublicIPv4 == "" {
		hpNetworkV1.PublicIPv4 = ipv4
	}
	if hpNetworkV1.PublicIPv6 == "" {
		hpNetworkV1.PublicIPv6 = ipv6
	}
	// networks contains network names, by HostExtensionNetworkV1.IPxAddresses has to be
	// indexed on network ID. Tries to convert if possible, if we already have correspondance
	// between network ID and network Name in Host definition
	if len(hpNetworkV1.NetworksByName) > 0 {
		ipv4Addresses := map[string]string{}
		ipv6Addresses := map[string]string{}
		for netname, netid := range hpNetworkV1.NetworksByName {
			if ip, ok := addresses[IPVersion.IPv4][netid]; ok {
				ipv4Addresses[netid] = ip
			} else if ip, ok := addresses[IPVersion.IPv4][netname]; ok {
				ipv4Addresses[netid] = ip
			} else {
				ipv4Addresses[netid] = ""
			}

			if ip, ok := addresses[IPVersion.IPv6][netid]; ok {
				ipv6Addresses[netid] = ip
			} else if ip, ok := addresses[IPVersion.IPv6][netname]; ok {
				ipv6Addresses[netid] = ip
			} else {
				ipv6Addresses[netid] = ""
			}
		}
		hpNetworkV1.IPv4Addresses = ipv4Addresses
		hpNetworkV1.IPv6Addresses = ipv6Addresses
	} else {
		networksByName := map[string]string{}
		ipv4Addresses := map[string]string{}
		ipv6Addresses := map[string]string{}
		for _, netname := range networks {
			networksByName[netname] = ""

			if ip, ok := addresses[IPVersion.IPv4][netname]; ok {
				ipv4Addresses[netname] = ip
			} else {
				ipv4Addresses[netname] = ""
			}

			if ip, ok := addresses[IPVersion.IPv6][netname]; ok {
				ipv6Addresses[netname] = ip
			} else {
				ipv6Addresses[netname] = ""
			}
		}
		hpNetworkV1.NetworksByName = networksByName
		// IPvxAddresses are here indexed by names... At least we have them...
		hpNetworkV1.IPv4Addresses = ipv4Addresses
		hpNetworkV1.IPv6Addresses = ipv6Addresses
	}

	return host.Properties.Set(HostProperty.NetworkV1, &hpNetworkV1)
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

func (client *Client) readGateway(networkID string) (*servers.Server, error) {
	m, err := metadata.NewGateway(client, networkID)
	found, err := m.Read()
	if err != nil {
		log.Debugf("Error reading gateway metadata: reading: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error reading gateway metadata"))
	}
	if !found {
		err := fmt.Errorf("unable to find gateway of network '%s'", networkID)
		log.Debugf("Error reading gateway metadata: not found : %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error reading gateway metadata: not found"))
	}

	gw, err := servers.Get(client.Compute, m.Get().ID).Extract()
	if err != nil {
		log.Debugf("Error reading gateway metadata: getting server : %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating Host: Unable to get gateway: %s", ProviderErrorToString(err)))
	}
	return gw, nil
}

// CreateHost creates an host satisfying request
func (client *Client) CreateHost(request model.HostRequest) (*model.Host, error) {
	host, err := client.createHost(request, false)
	if err != nil {
		log.Debugf("Error creating host: %+v", err)
		return nil, err
	}

	defer func() {
		if err != nil {
			derr := client.DeleteHost(host.ID)
			if derr != nil {
				log.Warnf("Error deleting host: %v", derr)
			}
		}
	}()

	// Saves host metadata
	err = metadata.SaveHost(client, host)
	if err != nil {
		return nil, err
	}

	return host, nil
}

// createHost ...
func (client *Client) createHost(request model.HostRequest, isGateway bool) (*model.Host, error) {
	msgFail := "Failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if isGateway && !request.PublicIP {
		return nil, fmt.Errorf("can't create a gateway without public IP")
	}

	// First check if name is not already used
	mh, err := metadata.LoadHost(client, request.ResourceName)
	if err != nil {
		log.Debugf("%+v", err)
		return nil, err
	}
	if mh != nil {
		return nil, fmt.Errorf("a host already exists with name '%s'", request.ResourceName)
	}

	// The Default Network is the first of the provided list, by convention
	defaultNetworkID := request.NetworkIDs[0]

	// Optional network gateway
	var defaultGateway *model.Host
	// If the host is not public it has to be created on a network owning a Gateway
	if !request.PublicIP {
		mgw, err := metadata.LoadGateway(client, defaultNetworkID)
		if err != nil {
			msg := fmt.Sprintf("private host requested without network")
			log.Debugf(utils.TitleFirst(msg))
			return nil, fmt.Errorf(msg)
		}
		if mgw != nil {
			defaultGateway = mgw.Get()
		}
	}

	// If a gateway is created, we need the CIDR for the userdata
	var (
		cidr           string
		defaultNetwork *model.Network
	)
	mn, err := metadata.LoadNetwork(client, defaultNetworkID)
	if err != nil {
		return nil, err
	}
	if mn == nil {
		return nil, fmt.Errorf("failed to load metadata of network '%s'", defaultNetworkID)
	}
	defaultNetwork = mn.Get()
	if isGateway {
		cidr = defaultNetwork.CIDR
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
	for _, n := range request.NetworkIDs {
		nets = append(nets, servers.Network{
			UUID: n,
		})
	}

	// If no key pair is supplied create one
	if request.KeyPair == nil {
		id, err := uuid.NewV4()
		if err != nil {
			msg := fmt.Sprintf("failed to create host UUID: %+v", err)
			log.Debugf(utils.TitleFirst(msg))
			return nil, fmt.Errorf(msg)
		}

		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
		request.KeyPair, err = client.CreateKeyPair(name)
		if err != nil {
			msg := fmt.Sprintf("failed to create host key pair: %+v", err)
			log.Debugf(utils.TitleFirst(msg))
			return nil, fmt.Errorf(msg)
		}
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData, err := userdata.Prepare(client, request, isGateway, request.KeyPair, defaultGateway, cidr)
	if err != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", err)
		log.Debugf(utils.TitleFirst(msg))
		return nil, fmt.Errorf(msg)
	}

	_, err = client.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get image: %s", ProviderErrorToString(err))
	}

	// Sets provider parameters to create host
	srvOpts := servers.CreateOpts{
		Name:           request.ResourceName,
		SecurityGroups: []string{client.SecurityGroup.Name},
		Networks:       nets,
		FlavorRef:      request.TemplateID,
		ImageRef:       request.ImageID,
		UserData:       userData,
	}

	// --- Initializes model.Host ---

	host := model.NewHost()
	host.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition

	hpNetworkV1 := propsv1.BlankHostNetwork

	// Tells if the host is a gateway
	hpNetworkV1.IsGateway = isGateway

	// Add gateway ID to Host definition
	if defaultGateway != nil {
		hpNetworkV1.DefaultGatewayID = defaultGateway.ID
	}

	// Adds default network information
	hpNetworkV1.DefaultNetworkID = defaultNetworkID
	hpNetworkV1.NetworksByID = map[string]string{defaultNetwork.ID: defaultNetwork.Name}
	hpNetworkV1.NetworksByName = map[string]string{defaultNetwork.Name: defaultNetwork.ID}

	// Adds other network information to Host instance
	for _, netID := range request.NetworkIDs {
		if netID != defaultNetworkID {
			mn, err := metadata.LoadNetwork(client, netID)
			if err != nil {
				return nil, err
			}
			if mn == nil {
				return nil, fmt.Errorf("failed to load metadata of network '%s'", netID)
			}
			name := mn.Get().Name
			hpNetworkV1.NetworksByID[netID] = name
			hpNetworkV1.NetworksByName[name] = netID
		}
	}

	// Updates Host Property NetworkV1 in host instance
	err = host.Properties.Set(HostProperty.NetworkV1, &hpNetworkV1)
	if err != nil {
		return nil, err
	}

	// --- query provider for host creation ---

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
			host, err = client.WaitHostReady(host, 5*time.Minute)
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
	if host == nil {
		return nil, errors.New("unexpected problem creating host")
	}

	// Starting from here, delete host if exiting with error
	defer func() {
		if err != nil {
			err := client.DeleteHost(host.ID)
			if err != nil {
				log.Warnf("Error deleting host: %v", err)
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
				err := floatingips.Delete(client.Compute, ip.ID).ExtractErr()
				if err != nil {
					log.Errorf("Error deleting Floating IP: %v", err)
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
			return nil, errors.Wrap(err, fmt.Sprintf(msg))
		}

		err = host.Properties.Get(HostProperty.NetworkV1, &hpNetworkV1)
		if err != nil {
			return nil, err
		}
		if IPVersion.IPv4.Is(ip.IP) {
			hpNetworkV1.PublicIPv4 = ip.IP
		} else if IPVersion.IPv6.Is(ip.IP) {
			hpNetworkV1.PublicIPv6 = ip.IP
		}

		// Updates Host Extension NetworkV1 in host instance
		err = host.Properties.Set(HostProperty.NetworkV1, &hpNetworkV1)
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

	retryErr := retry.WhileUnsuccessful(
		func() error {
			err = client.UpdateHost(host)
			if err != nil {
				return err
			}
			if host.LastState != HostState.STARTED {
				return fmt.Errorf("not in ready state (current state: %s)", host.LastState.String())
			}
			return nil
		},
		2*time.Second,
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return nil, fmt.Errorf("timeout waiting to get host '%s' information after %v", host.Name, timeout)
		}
		return nil, retryErr
	}
	err = client.UpdateHost(host)
	return host, err
}

// // UpdateHost updates the data inside host with the data from provider
// // TODO: move this method on the model.Host struct
// func (client *Client) UpdateHost(host *model.Host) error {
// 	var (
// 		server *servers.Server
// 		err    error
// 	)

// 	retryErr := retry.WhileUnsuccessful(
// 		func() error {
// 			server, err = servers.Get(client.Compute, host.ID).Extract()
// 			if err != nil {
// 				switch err.(type) {
// 				case gc.ErrDefault404:
// 					// If error is "resource not found", we want to return GopherCloud error as-is to be able
// 					// to behave differently in this special case. To do so, stop the retry
// 					return nil
// 				case gc.ErrDefault500:
// 					// When the response is "Internal Server Error", retries
// 					log.Println("received 'Internal Server Error', retrying servers.Get...")
// 					return err
// 				}
// 				// Any other error stops the retry
// 				err = fmt.Errorf("Error getting host '%s': %s", host.ID, ProviderErrorToString(err))
// 				return nil
// 			}
// 			//spew.Dump(server)
// 			if server.Status != "ERROR" && server.Status != "CREATING" {
// 				host.LastState = toHostState(server.Status)
// 				return nil
// 			}
// 			return fmt.Errorf("server not ready yet")
// 		},
// 		10*time.Second,
// 		1*time.Second,
// 	)
// 	if retryErr != nil {
// 		switch retryErr.(type) {
// 		case retry.ErrTimeout:
// 			return fmt.Errorf("failed to get host '%s' information after 10s: %s", host.ID, err.Error())
// 		}
// 	}
// 	if err != nil {
// 		return err
// 	}
// 	err = client.complementHost(host, server)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// GetHostState returns the current state of host identified by id
// hostParam can be a string or an instance of *model.Host; any other type will panic
func (client *Client) GetHostState(hostParam interface{}) (HostState.Enum, error) {
	var (
		host *model.Host
		err  error
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
	err = client.UpdateHost(host)
	if err != nil {
		return HostState.ERROR, err
	}
	return host.LastState, nil
}

// ListHosts lists available hosts
func (client *Client) ListHosts(all bool) ([]*model.Host, error) {
	if all {
		return client.listAllHosts()
	}
	return client.listMonitoredHosts()
}

// listAllHosts lists available hosts
func (client *Client) listAllHosts() ([]*model.Host, error) {
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

// listMonitoredHosts lists available hosts created by SafeScale (ie registered in object storage)
func (client *Client) listMonitoredHosts() ([]*model.Host, error) {
	var hosts []*model.Host
	m := metadata.NewHost(client)
	err := m.Browse(func(host *model.Host) error {
		hosts = append(hosts, host)
		return nil
	})
	if err != nil {
		return hosts, errors.Wrap(err, fmt.Sprintf("Error listing monitored hosts: browse"))
	}
	return hosts, nil
}

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to an host
func (client *Client) getFloatingIP(hostID string) (*floatingips.FloatingIP, error) {
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
func (client *Client) DeleteHost(ref string) error {
	m, err := metadata.LoadHost(client, ref)
	if err != nil {
		log.Debugf("Error deleting host: getting host metadata: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting host: getting host metadata"))
	}
	if m == nil {
		log.Debugf("Error deleting host: no host found: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Failed to find host '%s' in metadata", ref))
	}

	host := m.Get()
	id := host.ID
	if client.Cfg.UseFloatingIP {
		fip, err := client.getFloatingIP(id)
		if err == nil {
			if fip != nil {
				err = floatingips.DisassociateInstance(client.Compute, id, floatingips.DisassociateOpts{
					FloatingIP: fip.IP,
				}).ExtractErr()
				if err != nil {
					log.Debugf("Error deleting host: dissociate: %+v", err)
					return errors.Wrap(err, fmt.Sprintf("error deleting host %s : %s", host.Name, ProviderErrorToString(err)))
				}
				err = floatingips.Delete(client.Compute, fip.ID).ExtractErr()
				if err != nil {
					log.Debugf("Error deleting host: delete floating ip: %+v", err)
					return errors.Wrap(err, fmt.Sprintf("error deleting host %s : %s", host.Name, ProviderErrorToString(err)))
				}
			}
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
					// Resource not found, consider deletion succeeded (if the entry doesn't exist at all,
					// metadata deletion will return an error)
					return nil
				default:
					return fmt.Errorf("failed to submit host '%s' deletion: %s", host.Name, ProviderErrorToString(err))
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
					return fmt.Errorf("failed to acknowledge host '%s' deletion! %s", host.Name, err.Error())
				default:
					return innerRetryErr
				}
			}
			if !resourcePresent {
				return nil
			}
			return fmt.Errorf("host '%s' in state 'ERROR', retrying to delete", host.Name)
		},
		0,
		3*time.Minute,
	)
	if outerRetryErr != nil {
		log.Debugf("failed to remove host '%s': %s", host.Name, err.Error())
		return errors.Wrap(err, fmt.Sprintf("Error deleting host: retry error"))
	}
	return metadata.RemoveHost(client, host)
}

// StopHost stops the host identified by id
func (client *Client) StopHost(ref string) error {
	log.Println("Received stop petition")
	id := ref

	m, err := metadata.LoadHost(client, ref)
	if err != nil {
		log.Debugf("Error getting ssh config: loading host metadata: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error getting ssh config: loading host metadata"))
	}
	if m != nil {
		id = m.Get().ID
	}

	err = startstop.Stop(client.Compute, id).ExtractErr()
	if err != nil {
		log.Debugf("Error stopping host: stopping host: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("error stopping host : %s", ProviderErrorToString(err)))
	}
	return nil
}

// RebootHost ...
func (client *Client) RebootHost(ref string) error {
	log.Println("Received reboot petition")
	id := ref

	m, err := metadata.LoadHost(client, ref)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error rebooting host: loading host"))
	}
	if m != nil {
		id = m.Get().ID
	}

	err = servers.Reboot(client.Compute, id, servers.RebootOpts{Type: "HARD"}).ExtractErr()
	if err != nil {
		ftErr := fmt.Errorf("Error rebooting host [%s]: %s", id, ProviderErrorToString(err))
		log.Debug(ftErr)
		return errors.Wrap(err, ftErr.Error())
	}
	return nil
}

// StartHost starts the host identified by id
func (client *Client) StartHost(ref string) error {
	log.Println("Received start petition")
	id := ref

	m, err := metadata.LoadHost(client, ref)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error starting host: loading host"))
	}
	if m != nil {
		id = m.Get().ID
	}

	err = startstop.Start(client.Compute, id).ExtractErr()
	if err != nil {
		log.Debugf("Error starting host: starting host: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error starting host : %s", ProviderErrorToString(err)))
	}

	return nil
}

func (client *Client) getSSHConfig(host *model.Host) (*system.SSHConfig, error) {
	spew.Dump(host)

	sshConfig := system.SSHConfig{
		PrivateKey: host.PrivateKey,
		Port:       22,
		Host:       host.GetAccessIP(),
		User:       model.DefaultUser,
	}
	hpNetworkV1 := propsv1.HostNetwork{}
	err := host.Properties.Get(HostProperty.NetworkV1, &hpNetworkV1)
	if err != nil {
		return nil, err
	}
	if hpNetworkV1.DefaultGatewayID != "" {
		mgw, err := metadata.LoadHost(client, hpNetworkV1.DefaultGatewayID)
		if err != nil {
			log.Debugf("Error getting ssh config: getting host: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error getting ssh config: getting host"))
		}
		gw := mgw.Get()
		GatewayConfig := system.SSHConfig{
			PrivateKey: gw.PrivateKey,
			Port:       22,
			User:       model.DefaultUser,
			Host:       gw.GetAccessIP(),
		}
		sshConfig.GatewayConfig = &GatewayConfig
	}
	return &sshConfig, nil
}

// // GetSSHConfig creates SSHConfig to connect an host
// func (client *Client) GetSSHConfig(param interface{}) (*system.SSHConfig, error) {
// 	var (
// 		host *model.Host
// 	)

// 	switch param.(type) {
// 	case string:
// 		mh, err := metadata.LoadHost(client, param.(string))
// 		if err != nil {
// 			return nil, err
// 		}
// 		host = mh.Get()
// 	case *model.Host:
// 		host = param.(*model.Host)
// 	default:
// 		panic("param must be a string or a *model.Host!")
// 	}
// 	return client.getSSHConfig(host)
// }
