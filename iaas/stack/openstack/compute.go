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

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/utils/retry"

	uuid "github.com/satori/go.uuid"

	"github.com/CS-SI/SafeScale/iaas/resource/enums/HostExtension"
	"github.com/CS-SI/SafeScale/providers/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/enums/IPVersion"
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
func (s *Stack) ListImages() ([]model.Image, error) {
	opts := images.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := images.List(s.Compute, opts)

	var imgList []model.Image

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		imageList, err := images.ExtractImages(page)
		if err != nil {
			return false, err
		}

		for _, img := range imageList {
			imgList = append(imgList, model.Image{ID: img.ID, Name: img.Name})

		}
		return true, nil
	})
	if len(imgList) == 0 {
		if err != nil {
			return nil, fmt.Errorf("Error listing images: %s", ErrorToString(err))
		}
	}
	return imgList, nil
}

// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (*model.Image, error) {
	img, err := images.Get(s.Compute, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting image: %s", ErrorToString(err))
	}
	return &model.Image{ID: img.ID, Name: img.Name}, nil
}

// GetTemplate returns the Template referenced by id
func (s *Stack) GetTemplate(id string) (*model.HostTemplate, error) {
	// Try 10 seconds to get template
	var flv *flavors.Flavor
	err := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			var err error
			flv, err = flavors.Get(s.Compute, id).Extract()
			return err
		},
		10*time.Second,
	)
	if err != nil {
		return nil, fmt.Errorf("error getting template: %s", ErrorToString(err))
	}
	return &model.HostTemplate{
		HostSize: model.HostSize{
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
func (s *Stack) ListTemplates() ([]model.HostTemplate, error) {
	opts := flavors.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := flavors.ListDetail(s.Compute, opts)

	var flvList []model.HostTemplate

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		flavorList, err := flavors.ExtractFlavors(page)
		if err != nil {
			return false, err
		}

		for _, flv := range flavorList {
			ht := model.HostTemplate{
				HostSize: model.HostSize{
					Cores:    flv.VCPUs,
					RAMSize:  float32(flv.RAM) / 1000.0,
					DiskSize: flv.Disk,
				},
				ID:   flv.ID,
				Name: flv.Name,
			}
			flvList = append(flvList, ht)
		}
		return true, nil
	})
	if len(flvList) == 0 {
		if err != nil {
			return nil, err
		}
	}
	return flvList, nil
}

// CreateKeyPair creates and import a key pair
func (s *Stack) CreateKeyPair(name string) (*model.KeyPair, error) {
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
func (s *Stack) GetKeyPair(id string) (*model.KeyPair, error) {
	kp, err := keypairs.Get(s.Compute, id).Extract()
	if err != nil {
		return nil, err
	}
	return &model.KeyPair{
		ID:         kp.Name,
		Name:       kp.Name,
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
	}, nil
}

// ListKeyPairs lists available key pairs
func (s *Stack) ListKeyPairs() ([]model.KeyPair, error) {
	// Retrieve a pager (i.e. a paginated collection)
	pager := keypairs.List(s.Compute)

	var kpList []model.KeyPair

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		keyList, err := keypairs.ExtractKeyPairs(page)
		if err != nil {
			return false, err
		}

		for _, kp := range keyList {
			newKp := model.KeyPair{
				ID:         kp.Name,
				Name:       kp.Name,
				PublicKey:  kp.PublicKey,
				PrivateKey: kp.PrivateKey,
			}
			kpList = append(kpList, newKp)
		}
		return true, nil
	})
	if len(kpList) == 0 {
		if err != nil {
			return nil, err
		}
	}
	return kpList, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (s *Stack) DeleteKeyPair(id string) error {
	err := keypairs.Delete(s.Compute, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting key pair: %s", ErrorToString(err))
	}
	return nil
}

// toHostSize converts flavor attributes returned by OpenStack driver into api.Host
func (s *Stack) toHostSize(flavor map[string]interface{}) model.HostSize {
	if i, ok := flavor["id"]; ok {
		fid := i.(string)
		tpl, err := s.GetTemplate(fid)
		if err == nil {
			return tpl.HostSize
		}
	}
	if _, ok := flavor["vcpus"]; ok {
		return model.HostSize{
			Cores:    flavor["vcpus"].(int),
			DiskSize: flavor["disk"].(int),
			RAMSize:  flavor["ram"].(float32) / 1000.0,
		}
	}
	return model.HostSize{}
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
func (s *Stack) convertAdresses(addresses map[string]interface{}) (map[IPVersion.Enum][]string, string, string) {
	addrs := make(map[IPVersion.Enum][]string)
	var AcccessIPv4 string
	var AcccessIPv6 string
	for n, obj := range addresses {
		for _, networkAddresses := range obj.([]interface{}) {
			address := networkAddresses.(map[string]interface{})
			version := address["version"].(float64)
			fixedIP := address["addr"].(string)
			if n == s.CfgOpts.ProviderNetwork {
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

// toHost converts an OpenStack server into model.Host
func (s *Stack) toHost(server *servers.Server) *model.Host {
	adresses, ipv4, ipv6 := s.convertAdresses(server.Addresses)
	if ipv4 != "" {
		server.AccessIPv4 = ipv4
	}
	if ipv6 != "" {
		server.AccessIPv6 = ipv6
	}

	host := model.Host{
		ID:           server.ID,
		ResourceName: server.Name,
		//PrivateIPsV4: adresses[IPVersion.IPv4],
		//PrivateIPsV6: adresses[IPVersion.IPv6],
		AccessIPv4: server.AccessIPv4,
		AccessIPv6: server.AccessIPv6,
		Size:       s.toHostSize(server.Flavor),
		//State:        toHostState(server.Status),
	}
	// m, err := metadata.LoadHost(providers.FromStack(s), server.ID)
	// if err == nil && m != nil {
	// 	hostDef := m.Get()
	// 	//host.GatewayID = hostDef.GatewayID
	// 	host.PrivateKey = hostDef.PrivateKey
	// 	//Floating IP management
	// 	if host.AccessIPv4 == "" {
	// 		host.AccessIPv4 = hostDef.AccessIPv4
	// 	}
	// 	if host.AccessIPv6 == "" {
	// 		host.AccessIPv6 = hostDef.AccessIPv6
	// 	}
	// }
	return &host
}

func (s *Stack) readGateway(networkID string) (*servers.Server, error) {
	network, err := s.GetNetwork(networkID)
	if err != nil {
		return nil, err
	}

	gw, err := servers.Get(s.Compute, network.GatewayID).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating Host: Unable to get gateway: %s", ErrorToString(err))
	}
	return gw, nil
}

// CreateHost creates an host satisfying request
func (s *Stack) CreateHost(request model.HostRequest) (*model.Host, error) {
	host, err := s.createHost(request, false)
	if err != nil {
		return nil, err
	}

	// err = metadata.SaveHost(providers.FromClient(s), host, request.NetworkIDs[0])
	// if err != nil {
	// 	nerr := s.DeleteHost(host.ID)
	// 	if nerr != nil {
	// 		log.Warnf("Error deleting host: %v", nerr)
	// 	}
	// 	return nil, fmt.Errorf("error creating host: %s", ProviderErrorToString(err))
	// }

	return host, nil
}

// createHost ...
func (s *Stack) createHost(request model.HostRequest, isGateway bool) (*model.Host, error) {
	msgFail := "Failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.Name)

	// Optional network gateway
	var gw *model.Host
	// If the host is not public it has to be created on a network owning a Gateway
	if !request.PublicIP {
		gwServer, err := s.readGateway(request.NetworkIDs[0])

		if err != nil {
			return nil, fmt.Errorf(msgFail, "no private host can be created on a network without gateway")
		}
		gw, err := s.GetHost(gwServer.ID)
		if err != nil {
			return nil, fmt.Errorf(msgFail, fmt.Sprintf("bad state, Gateway for network '%s' is not accessible", request.NetworkIDs[0]))
		}
	}

	// If a gateway is created, we need the CIDR for the userdata
	var cidr string
	if isGateway {
		network, err := s.GetNetwork(request.NetworkIDs[0])
		if err != nil {
			return nil, err
		}
		cidr = network.CIDR
	}

	var nets []servers.Network
	// If floating IPs are not used and host is public
	// then add provider network to host networks
	if !s.CfgOpts.UseFloatingIP && request.PublicIP {
		nets = append(nets, servers.Network{
			UUID: s.ProviderNetworkID,
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
			return nil, fmt.Errorf("error creating UID : %v", err)
		}

		name := fmt.Sprintf("%s_%s", request.Name, id)
		kp, err = s.CreateKeyPair(name)
		if err != nil {
			return nil, fmt.Errorf(msgFail, ErrorToString(err))
		}
	}

	userData, err := userdata.Prepare(s, request, isGateway, kp, gw, cidr)
	if err != nil {
		return nil, err
	}

	// Create host
	srvOpts := servers.CreateOpts{
		Name:           request.Name,
		SecurityGroups: []string{s.SecurityGroup.Name},
		Networks:       nets,
		FlavorRef:      request.TemplateID,
		ImageRef:       request.ImageID,
		UserData:       userData,
	}

	// Retry creation until success, for 10 minutes
	var host *model.Host
	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			server, err := servers.Create(s.Compute, keypairs.CreateOptsExt{
				CreateOptsBuilder: srvOpts,
			}).Extract()
			if err != nil {
				if server != nil {
					servers.Delete(s.Compute, server.ID)
				}
				msg := fmt.Sprintf(msgFail, ErrorToString(err))
				// TODO Gotcha !!
				log.Debugf(msg)
				return fmt.Errorf(msg)
			}
			// Wait that Host is ready
			host, err = s.WaitHostReady(server.ID, 5*time.Minute)
			if err != nil {
				servers.Delete(s.Compute, server.ID)
				msg := fmt.Sprintf(msgFail, ErrorToString(err))
				// TODO Gotcha !!
				log.Debugf(msg)
				return fmt.Errorf(msg)
			}
			return nil
		},
		10*time.Minute,
	)

	if err != nil {
		return nil, err
	}

	if host == nil {
		return nil, errors.New("unexpected problem creating host")
	}

	// Add gateway ID to Host definition
	var gwID string
	if gw != nil {
		gwID = gw.ID
		host.GatewayID = gwID
	} else {
		log.Debugf("There was a problem with gateway ID...")
		host.GatewayID = ""
	}

	host.PrivateKey = kp.PrivateKey

	// if Floating IP are not used or no public address is requested
	if s.CfgOpts.UseFloatingIP && request.PublicIP {
		// Create the floating IP
		ip, err := floatingips.Create(s.Compute, floatingips.CreateOpts{
			Pool: s.AuthOpts.FloatingIPPool,
		}).Extract()
		if err != nil {
			servers.Delete(s.Compute, host.ID)
			return nil, fmt.Errorf(msgFail, ErrorToString(err))
		}

		// Associate floating IP to host
		err = floatingips.AssociateInstance(s.Compute, host.ID, floatingips.AssociateOpts{
			FloatingIP: ip.IP,
		}).ExtractErr()
		if err != nil {
			floatingips.Delete(s.Compute, ip.ID)
			servers.Delete(s.Compute, host.ID)
			msg := fmt.Sprintf(msgFail, ErrorToString(err))
			log.Errorf(msg)
			return nil, fmt.Errorf(msg)
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
func (s *Stack) WaitHostReady(hostID string, timeout time.Duration) (*model.Host, error) {
	var (
		server *servers.Server
		err    error
		broken bool
	)

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			server, err = servers.Get(s.Compute, hostID).Extract()
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
		return nil, retryErr
	}
	if broken {
		return nil, fmt.Errorf("host '%s' is in '%s' state", server.Name, server.Status)
	}
	return s.toHost(server), nil
}

// GetHost returns the host identified by id
func (s *Stack) GetHost(id string) (*model.Host, error) {
	var (
		server *servers.Server
		err    error
	)

	retryErr := retry.WhileUnsuccessful(
		func() error {
			server, err = servers.Get(s.Compute, id).Extract()
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
				err = fmt.Errorf("Error getting host '%s': %s", id, ErrorToString(err))
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
			return nil, fmt.Errorf("failed to get host '%s' information after 10s: %s", id, err.Error())
		}
	}
	if err != nil {
		return nil, err
	}
	return s.toHost(server), nil
}

// ListHosts lists available hosts
func (s *Stack) ListHosts() ([]model.Host, error) {
	pager := servers.List(s.Compute, servers.ListOpts{})
	var hosts []model.Host
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}

		for _, srv := range list {
			hosts = append(hosts, *s.toHost(&srv))
		}
		return true, nil
	})
	if len(hosts) == 0 && err != nil {
		return nil, fmt.Errorf("error listing hosts : %s", ErrorToString(err))
	}
	return hosts, nil
}

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to an host
func (s *Stack) getFloatingIP(hostID string) (*floatingips.FloatingIP, error) {
	pager := floatingips.List(s.Compute)
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
			return nil, fmt.Errorf("No floating IP found for host '%s': %s", hostID, ErrorToString(err))
		}
		return nil, fmt.Errorf("No floating IP found for host '%s'", hostID)

	}
	if len(fips) > 1 {
		return nil, fmt.Errorf("Configuration error, more than one Floating IP associated to host '%s'", hostID)
	}
	return &fips[0], nil
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(id string) error {
	host, err := s.GetHost(id)
	if err != nil {
		return err
	}
	if s.CfgOpts.UseFloatingIP {
		fip, err := s.getFloatingIP(id)
		if err == nil {
			if fip != nil {
				err = floatingips.DisassociateInstance(s.Compute, id, floatingips.DisassociateOpts{
					FloatingIP: fip.IP,
				}).ExtractErr()
				if err != nil {
					return fmt.Errorf("error deleting host '%s' : %s", host.ResourceName, ErrorToString(err))
				}
				err = floatingips.Delete(s.Compute, fip.ID).ExtractErr()
				if err != nil {
					return fmt.Errorf("error deleting host '%s' : %s", host.ResourceName, ErrorToString(err))
				}
			}
		}
	}

	// Try to remove host for 3 minutes
	outerRetryErr := retry.WhileUnsuccessful(
		func() error {
			resourcePresent := true
			// 1st, send delete host order
			err := servers.Delete(s.Compute, id).ExtractErr()
			if err != nil {
				switch err.(type) {
				case gc.ErrDefault404:
					// Resource not found, consider deletion succeeded (if the entry doesn't exist at all,
					// metadata deletion will return an error)
					return nil
				default:
					return fmt.Errorf("failed to submit host '%s' deletion: %s", host.ResourceName, ErrorToString(err))
				}
			}
			// 2nd, check host status every 5 seconds until check failed.
			// If check succeeds but state is Error, retry the deletion.
			// If check fails and error isn't 'resource not found', retry
			innerRetryErr := retry.WhileUnsuccessfulDelay5Seconds(
				func() error {
					host, err := servers.Get(s.Compute, id).Extract()
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
					return fmt.Errorf("failed to acknowledge host '%s' deletion! %s", host.ResourceName, err.Error())
				default:
					return innerRetryErr
				}
			}
			if !resourcePresent {
				return nil
			}
			return fmt.Errorf("host '%s' in state 'ERROR', retrying to delete", host.ResourceName)
		},
		0,
		3*time.Minute,
	)
	if outerRetryErr != nil {
		log.Printf("failed to remove host '%s': %s", host.ResourceName, err.Error())
		return err
	}
	return nil
}

// StopHost stops the host identified by id
func (s *Stack) StopHost(id string) error {
	err := startstop.Stop(s.Compute, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("error stopping host : %s", ErrorToString(err))
	}
	return nil
}

// RebootHost forcibly reboots a host
func (s *Stack) RebootHost(id string) error {
	err := servers.Reboot(s.Compute, id, servers.RebootOpts{Type: "HARD"}).ExtractErr()
	if err != nil {
		ftErr := fmt.Errorf("error rebooting host [%s]: %s", id, ErrorToString(err))
		log.Println(ftErr)
		return ftErr
	}
	return nil
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(id string) error {
	err := startstop.Start(s.Compute, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("error starting host : %s", ErrorToString(err))
	}

	return nil
}

// GetSSHConfig creates SSHConfig to connect an host
func (s *Stack) GetSSHConfig(id string) (*system.SSHConfig, error) {
	host, err := s.GetHost(id)
	if err != nil {
		return nil, err
	}
	ip := host.GetAccessIP()
	sshConfig := system.SSHConfig{
		PrivateKey: host.PrivateKey,
		Port:       22,
		Host:       ip,
		User:       iaas.DefaultUser,
	}
	anon, err := host.GetExtension(HostExtension.NetworkV1)
	if err != nil {
		return nil, err
	}
	ex := anon.(model.HostExtensionNetworkV1)
	if ex.GatewayID != "" {
		gw, err := s.GetHost(ex.GatewayID)
		if err != nil {
			return nil, err
		}
		ip := gw.GetAccessIP()
		GatewayConfig := system.SSHConfig{
			PrivateKey: gw.PrivateKey,
			Port:       22,
			User:       iaas.DefaultUser,
			Host:       ip,
		}
		sshConfig.GatewayConfig = &GatewayConfig
	}

	return &sshConfig, nil
}
