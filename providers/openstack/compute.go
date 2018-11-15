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
	"github.com/pkg/errors"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/utils/retry"

	uuid "github.com/satori/go.uuid"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/enums/IPVersion"
	metadata "github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/userdata"

	"github.com/CS-SI/SafeScale/system"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/startstop"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/pagination"

	"golang.org/x/crypto/ssh"
)

// ListImages lists available OS images
func (client *Client) ListImages(all bool) ([]api.Image, error) {
	opts := images.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := images.List(client.Compute, opts)

	var imgList []api.Image

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		imageList, err := images.ExtractImages(page)
		if err != nil {
			log.Debugf("Error listing images: %+v", err)
			return false, errors.Wrap(err, fmt.Sprintf("Error listing images"))
		}

		for _, img := range imageList {
			imgList = append(imgList, api.Image{ID: img.ID, Name: img.Name})
		}
		return true, nil
	})
	if (len(imgList) == 0) || (err != nil){
		if err != nil {
			log.Debugf("Error listing images: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing images: %s", ProviderErrorToString(err)))
		}
		// log.Debugf("Image list empty !")
	}
	return imgList, nil
}

// GetImage returns the Image referenced by id
func (client *Client) GetImage(id string) (*api.Image, error) {
	img, err := images.Get(client.Compute, id).Extract()
	if err != nil {
		log.Debugf("Error getting image: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting image: %s", ProviderErrorToString(err)))
	}
	return &api.Image{ID: img.ID, Name: img.Name}, nil
}

// GetTemplate returns the Template referenced by id
func (client *Client) GetTemplate(id string) (*api.HostTemplate, error) {
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
	return &api.HostTemplate{
		HostSize: api.HostSize{
			Cores:    flv.VCPUs,
			RAMSize:  float32(flv.RAM) / 1000.0,
			DiskSize: flv.Disk,
		},
		ID:   flv.ID,
		Name: flv.Name,
	}, nil
}

// ListTemplates lists available Host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (client *Client) ListTemplates(all bool) ([]api.HostTemplate, error) {
	opts := flavors.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := flavors.ListDetail(client.Compute, opts)

	var flvList []api.HostTemplate

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		flavorList, err := flavors.ExtractFlavors(page)
		if err != nil {
			return false, err
		}

		for _, flv := range flavorList {

			flvList = append(flvList, api.HostTemplate{
				HostSize: api.HostSize{
					Cores:    flv.VCPUs,
					RAMSize:  float32(flv.RAM) / 1000.0,
					DiskSize: flv.Disk,
				},
				ID:   flv.ID,
				Name: flv.Name,
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
func (client *Client) CreateKeyPair(name string) (*api.KeyPair, error) {
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
	return &api.KeyPair{
		ID:         name,
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: priKey,
	}, nil
}

// GetKeyPair returns the key pair identified by id
func (client *Client) GetKeyPair(id string) (*api.KeyPair, error) {
	kp, err := keypairs.Get(client.Compute, id).Extract()
	if err != nil {
		log.Debugf("Error getting keypair: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting keypair"))
	}
	return &api.KeyPair{
		ID:         kp.Name,
		Name:       kp.Name,
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
	}, nil
}

// ListKeyPairs lists available key pairs
func (client *Client) ListKeyPairs() ([]api.KeyPair, error) {

	// Retrieve a pager (i.e. a paginated collection)
	pager := keypairs.List(client.Compute)

	var kpList []api.KeyPair

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		keyList, err := keypairs.ExtractKeyPairs(page)
		if err != nil {
			return false, err
		}

		for _, kp := range keyList {
			kpList = append(kpList, api.KeyPair{
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

// toHostSize converts flavor attributes returned by OpenStack driver into api.Host
func (client *Client) toHostSize(flavor map[string]interface{}) api.HostSize {
	if i, ok := flavor["id"]; ok {
		fid := i.(string)
		tpl, err := client.GetTemplate(fid)
		if err == nil {
			return tpl.HostSize
		}
	}
	if _, ok := flavor["vcpus"]; ok {
		return api.HostSize{
			Cores:    flavor["vcpus"].(int),
			DiskSize: flavor["disk"].(int),
			RAMSize:  flavor["ram"].(float32) / 1000.0,
		}
	}
	return api.HostSize{}
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

// convertAdresses converts adresses returned by the OpenStack driver arrange them by version in a map
func (client *Client) convertAdresses(addresses map[string]interface{}) (map[IPVersion.Enum][]string, string, string) {
	addrs := make(map[IPVersion.Enum][]string)
	var AcccessIPv4 string
	var AcccessIPv6 string
	for n, obj := range addresses {

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
					addrs[IPVersion.IPv4] = append(addrs[IPVersion.IPv4], fixedIP)
				case 6:
					addrs[IPVersion.IPv6] = append(addrs[IPVersion.IPv4], fixedIP)
				}
			}

		}
	}
	return addrs, AcccessIPv4, AcccessIPv6
}

// toHost converts an OpenStack server into api Host
func (client *Client) toHost(server *servers.Server) *api.Host {
	adresses, ipv4, ipv6 := client.convertAdresses(server.Addresses)
	if ipv4 != "" {
		server.AccessIPv4 = ipv4
	}
	if ipv6 != "" {
		server.AccessIPv6 = ipv6
	}

	host := api.Host{
		ID:           server.ID,
		Name:         server.Name,
		PrivateIPsV4: adresses[IPVersion.IPv4],
		PrivateIPsV6: adresses[IPVersion.IPv6],
		AccessIPv4:   server.AccessIPv4,
		AccessIPv6:   server.AccessIPv6,
		Size:         client.toHostSize(server.Flavor),
		State:        toHostState(server.Status),
	}
	m, err := metadata.LoadHost(providers.FromClient(client), server.ID)
	if err == nil && m != nil {
		hostDef := m.Get()
		host.GatewayID = hostDef.GatewayID
		host.PrivateKey = hostDef.PrivateKey
		//Floating IP management
		if host.AccessIPv4 == "" {
			host.AccessIPv4 = hostDef.AccessIPv4
		}
		if host.AccessIPv6 == "" {
			host.AccessIPv6 = hostDef.AccessIPv6
		}
	}
	return &host
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
	m, err := metadata.NewGateway(providers.FromClient(client), networkID)
	if err != nil {
		log.Debugf("Error reading gateway metadata: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error reading gateway metadata"))
	}

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
func (client *Client) CreateHost(request api.HostRequest) (*api.Host, error) {
	host, err := client.createHost(request, false)
	if err != nil {
		log.Debugf("Error creating host: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating host"))
	}

	err = metadata.SaveHost(providers.FromClient(client), host, request.NetworkIDs[0])
	if err != nil {
		nerr := client.DeleteHost(host.ID)
		if nerr != nil {
			log.Warnf("Error deleting host: %v", nerr)
		}

		log.Debugf("Error creating host: save host: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("error creating host: %s", ProviderErrorToString(err)))
	}

	return host, nil
}

// createHost ...
func (client *Client) createHost(request api.HostRequest, isGateway bool) (*api.Host, error) {
	msgFail := "Failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.Name)

	// First check if name is not already used
	m, err := metadata.LoadHost(providers.FromClient(client), request.Name)
	if err != nil {
		log.Debugf("Error creating host: loading host: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating host: loading host"))
	}
	if m != nil {
		err := fmt.Errorf(msgFail, fmt.Sprintf("a host already exists with name '%s'", request.Name))
		log.Debugf("Error creating host: load host: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating host: load host"))
	}

	// Optional network gateway
	var gw *api.Host
	// If the host is not public it has to be created on a network owning a Gateway
	if !request.PublicIP {
		gwServer, err := client.readGateway(request.NetworkIDs[0])

		if err != nil {
			log.Debugf("Error creating host: read gateway: %+v", err)
			err := fmt.Errorf(msgFail, "no private host can be created on a network without gateway")
			return nil, errors.Wrap(err, fmt.Sprintf("Error creating host: read gateway"))
		}
		m, err := metadata.LoadHost(providers.FromClient(client), gwServer.ID)
		if err != nil {
			log.Debugf("Error creating host: load host: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf(msgFail, fmt.Sprintf("bad state, Gateway for network '%s' is not accessible", request.NetworkIDs[0])))
		}
		if m != nil {
			gw = m.Get()
		}
	}
	// If a gateway is created, we need the CIDR for the userdata
	var cidr string
	if isGateway {
		m, err := metadata.LoadNetwork(providers.FromClient(client), request.NetworkIDs[0])
		if err != nil {
			log.Debugf("Error creating host: load network: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error creating host: load network"))
		}
		if m == nil {
			return nil, fmt.Errorf(msgFail, fmt.Sprintf("failed to load metadata of network '%s'", request.NetworkIDs[0]))
		}
		network := m.Get()
		cidr = network.CIDR
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

	// Prepare key pair
	kp := request.KeyPair

	//If no key pair is supplied create one
	if kp == nil {
		id, err := uuid.NewV4()
		if err != nil {
			log.Debugf("Error creating host: error creating UID: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("error creating UID : %v", err))
		}

		name := fmt.Sprintf("%s_%s", request.Name, id)
		kp, err = client.CreateKeyPair(name)
		if err != nil {
			log.Debugf("Error creating host: creating key pair: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf(msgFail, ProviderErrorToString(err)))
		}
	}

	userData, err := userdata.Prepare(client, request, isGateway, kp, gw, cidr)
	if err != nil {
		log.Debugf("Error creating host: preparing user data: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating host: preparing user data"))
	}

	// Create host
	srvOpts := servers.CreateOpts{
		Name:           request.Name,
		SecurityGroups: []string{client.SecurityGroup.Name},
		Networks:       nets,
		FlavorRef:      request.TemplateID,
		ImageRef:       request.ImageID,
		UserData:       userData,
	}

	// Retry creation until success, for 10 minutes
	var host *api.Host
	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			server, err := servers.Create(client.Compute, keypairs.CreateOptsExt{
				CreateOptsBuilder: srvOpts,
			}).Extract()
			if err != nil {
				if server != nil {
					servers.Delete(client.Compute, server.ID)
				}
				msg := fmt.Sprintf(msgFail, ProviderErrorToString(err))

				log.Warnf(msg)
				return fmt.Errorf(msg)
			}
			// Wait that Host is ready
			host, err = client.WaitHostReady(server.ID, 5*time.Minute)
			if err != nil {
				servers.Delete(client.Compute, server.ID)
				msg := fmt.Sprintf(msgFail, ProviderErrorToString(err))

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
		return nil, errors.New("Unexpected problem creating host...")
	}

	// Add gateway ID to Host definition
	var gwID string
	if gw != nil {
		gwID = gw.ID
		host.GatewayID = gwID
	} else {
		host.GatewayID = ""
	}

	host.PrivateKey = kp.PrivateKey

	// if Floating IP are not used or no public address is requested
	if client.Cfg.UseFloatingIP && request.PublicIP {
		// Create the floating IP
		ip, err := floatingips.Create(client.Compute, floatingips.CreateOpts{
			Pool: client.Opts.FloatingIPPool,
		}).Extract()
		if err != nil {
			// TODO Don't ignore deleteresult
			servers.Delete(client.Compute, host.ID)
			log.Debugf("Error creating host: floating ip: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf(msgFail, ProviderErrorToString(err)))
		}

		// Associate floating IP to host
		err = floatingips.AssociateInstance(client.Compute, host.ID, floatingips.AssociateOpts{
			FloatingIP: ip.IP,
		}).ExtractErr()
		if err != nil {
			floatingips.Delete(client.Compute, ip.ID)
			servers.Delete(client.Compute, host.ID)
			msg := fmt.Sprintf(msgFail, ProviderErrorToString(err))
			log.Debugf(msg)
			return nil, errors.Wrap(err, fmt.Sprintf(msg))
		}

		if IPVersion.IPv4.Is(ip.IP) {
			host.AccessIPv4 = ip.IP
		} else if IPVersion.IPv6.Is(ip.IP) {
			host.AccessIPv6 = ip.IP
		}
	}
	log.Infoln(msgSuccess)

	return host, nil
}

// WaitHostReady waits an host achieve ready state
func (client *Client) WaitHostReady(hostID string, timeout time.Duration) (*api.Host, error) {
	var (
		server *servers.Server
		err    error
		broken bool
	)

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			server, err = servers.Get(client.Compute, hostID).Extract()
			if err != nil {
				return err
			}
			if server.Status == "ERROR" {
				broken = true
				return nil
			}
			if server.Status != "ACTIVE" {
				return fmt.Errorf("host '%s' is in state '%s'", server.Name, server.Status)
			}
			return nil
		},
		timeout,
	)
	if retryErr != nil {
		return nil, errors.Wrap(retryErr, fmt.Sprintf("Retry error"))
	}
	if broken {
		return nil, fmt.Errorf("host '%s' is in '%s' state", server.Name, server.Status)
	}
	return client.toHost(server), nil
}

// GetHost returns the host identified by id
func (client *Client) GetHost(ref string) (*api.Host, error) {
	var (
		server *servers.Server
		err    error
		id     string
	)

	m, err := metadata.LoadHost(providers.FromClient(client), ref)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting host: loading host metadata"))
	}
	if m == nil {
		return nil, providers.ResourceNotFoundError("host", ref)
	}
	id = m.Get().ID

	retryErr := retry.WhileUnsuccessful(
		func() error {
			server, err = servers.Get(client.Compute, id).Extract()
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
				err = fmt.Errorf("Error getting host '%s': %s", id, ProviderErrorToString(err))
				return nil
			}
			return nil
		},
		10*time.Second,
		1*time.Second,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return nil, errors.Wrap(retryErr, fmt.Sprintf("failed to get host '%s' information after 10s: %s", id, retryErr.Error()))
		}
	}
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting host: getting compute client"))
	}
	return client.toHost(server), nil
}

//ListHosts lists available hosts
func (client *Client) ListHosts(all bool) ([]api.Host, error) {
	if all {
		return client.listAllHosts()
	}
	return client.listMonitoredHosts()
}

// listAllHosts lists available hosts
func (client *Client) listAllHosts() ([]api.Host, error) {
	pager := servers.List(client.Compute, servers.ListOpts{})
	var hosts []api.Host
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}

		for _, srv := range list {
			hosts = append(hosts, *client.toHost(&srv))
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
func (client *Client) listMonitoredHosts() ([]api.Host, error) {
	var hosts []api.Host
	m := metadata.NewHost(providers.FromClient(client))
	err := m.Browse(func(host *api.Host) error {
		hosts = append(hosts, *host)
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
	m, err := metadata.LoadHost(providers.FromClient(client), ref)
	if err != nil {
		log.Debugf("Error deleting host: getting host metadata: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting host: getting host metadata"))
	}
	if m == nil {
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
					return fmt.Errorf("failed to acknowledge host '%s' deletion! %s", host.Name, innerRetryErr.Error())
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
		log.Debugf("failed to remove host '%s': %s", host.Name, outerRetryErr.Error())
		return errors.Wrap(err, fmt.Sprintf("Error deleting host: retry error"))
	}
	return metadata.RemoveHost(providers.FromClient(client), host)
}

// StopHost stops the host identified by id
func (client *Client) StopHost(ref string) error {
	log.Println("Received stop petition")
	id := ref

	m, err := metadata.LoadHost(providers.FromClient(client), ref)
	if err != nil {
		log.Debugf("Error getting ssh config: loading host metadata: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error getting ssh config: loading host metadata"))
	}
	if m != nil {
		host := m.Get()
		id = host.ID
	}

	err = startstop.Stop(client.Compute, id).ExtractErr()
	if err != nil {
		log.Debugf("Error stopping host: stopping host: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("error stopping host : %s", ProviderErrorToString(err)))
	}
	return nil
}

func (client *Client) RebootHost(ref string) error {
	log.Println("Received reboot petition")
	id := ref

	m, err := metadata.LoadHost(providers.FromClient(client), ref)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error rebooting host: loading host"))
	}
	if m != nil {
		host := m.Get()
		id = host.ID
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

	m, err := metadata.LoadHost(providers.FromClient(client), ref)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("Error starting host: loading host"))
	}
	if m != nil {
		host := m.Get()
		id = host.ID
	}

	err = startstop.Start(client.Compute, id).ExtractErr()
	if err != nil {
		log.Debugf("Error starting host: starting host: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error starting host : %s", ProviderErrorToString(err)))
	}

	return nil
}

func (client *Client) getSSHConfig(host *api.Host) (*system.SSHConfig, error) {

	ip := host.GetAccessIP()
	sshConfig := system.SSHConfig{
		PrivateKey: host.PrivateKey,
		Port:       22,
		Host:       ip,
		User:       api.DefaultUser,
	}
	if host.GatewayID != "" {
		gw, err := client.GetHost(host.GatewayID)
		if err != nil {
			log.Debugf("Error getting ssh config: getting host: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error getting ssh config: getting host"))
		}
		ip := gw.GetAccessIP()
		GatewayConfig := system.SSHConfig{
			PrivateKey: gw.PrivateKey,
			Port:       22,
			User:       api.DefaultUser,
			Host:       ip,
		}
		sshConfig.GatewayConfig = &GatewayConfig
	}

	return &sshConfig, nil

}

//GetSSHConfig creates SSHConfig to connect an host
func (client *Client) GetSSHConfig(id string) (*system.SSHConfig, error) {
	host, err := client.GetHost(id)
	if err != nil {
		log.Debugf("Error getting ssh config: getting host: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting ssh config: getting host"))
	}
	return client.getSSHConfig(host)
}
