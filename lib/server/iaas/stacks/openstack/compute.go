/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/gophercloud/gophercloud"
	az "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/availabilityzones"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/startstop"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/regions"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ListRegions ...
func (s *Stack) ListRegions() ([]string, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, true, "").WithStopwatch().Entering().OnExitTrace()()

	listOpts := regions.ListOpts{
		ParentRegionID: "RegionOne",
	}

	var results []string
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
func (s *Stack) ListAvailabilityZones() (list map[string]bool, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

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
		logrus.Warnf("no Availability Zones detected !")
	}

	return azList, nil
}

// ListImages lists available OS images
func (s *Stack) ListImages() (imgList []abstract.Image, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	opts := images.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	pager := images.List(s.ComputeClient, opts)

	// Define an anonymous function to be executed on each page's iteration
	err = pager.EachPage(func(page pagination.Page) (bool, error) {
		imageList, err := images.ExtractImages(page)
		if err != nil {
			return false, err
		}

		for _, img := range imageList {
			imgList = append(imgList, abstract.Image{ID: img.ID, Name: img.Name})

		}
		return true, nil
	})
	if (len(imgList) == 0) || (err != nil) {
		if err != nil {
			return nil, scerr.Wrap(err, fmt.Sprintf("error listing images: %s", ProviderErrorToString(err)))
		}
		logrus.Debugf("Image list empty !")
	}
	return imgList, nil
}

// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (image *abstract.Image, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	img, err := images.Get(s.ComputeClient, id).Extract()
	if err != nil {
		return nil, scerr.Wrap(err, fmt.Sprintf("error getting image: %s", ProviderErrorToString(err)))
	}
	return &abstract.Image{ID: img.ID, Name: img.Name}, nil
}

// GetTemplate returns the Template referenced by id
func (s *Stack) GetTemplate(id string) (template *abstract.HostTemplate, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Try 10 seconds to get template
	var flv *flavors.Flavor
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			var err error
			flv, err = flavors.Get(s.ComputeClient, id).Extract()
			return err
		},
		2*temporal.GetDefaultDelay(),
	)
	if retryErr != nil {
		return nil, scerr.Wrap(retryErr, fmt.Sprintf("error getting template: %s", ProviderErrorToString(retryErr)))
	}
	return &abstract.HostTemplate{
		Cores:    flv.VCPUs,
		RAMSize:  float32(flv.RAM) / 1000.0,
		DiskSize: flv.Disk,
		ID:       flv.ID,
		Name:     flv.Name,
	}, nil
}

// ListTemplates lists available Host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (s *Stack) ListTemplates() ([]abstract.HostTemplate, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()

	opts := flavors.ListOpts{}

	// Retrieve a pager (i.e. a paginated collection)
	var (
		flvList []abstract.HostTemplate
		pager   pagination.Pager
	)

	// Define an anonymous function to be executed on each page's iteration
	err := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			pager = flavors.ListDetail(s.ComputeClient, opts)
			return pager.EachPage(func(page pagination.Page) (bool, error) {
				flavorList, err := flavors.ExtractFlavors(page)
				if err != nil {
					return false, err
				}
				for _, flv := range flavorList {
					flvList = append(flvList, abstract.HostTemplate{
						Cores:    flv.VCPUs,
						RAMSize:  float32(flv.RAM) / 1000.0,
						DiskSize: flv.Disk,
						ID:       flv.ID,
						Name:     flv.Name,
					})
				}
				return true, nil
			})
		},
		time.Minute*2,
	)
	if err != nil {
		switch err.(type) {
		case scerr.ErrTimeout:
			return nil, err
		default:
			spew.Dump(pager.Err)
			return nil, scerr.Wrap(err, fmt.Sprintf("error listing templates"))
		}
	}
	if len(flvList) == 0 {
		logrus.Debugf("Template list empty.")
	}
	return flvList, nil
}

// CreateKeyPair creates and import a key pair
func (s *Stack) CreateKeyPair(name string) (*abstract.KeyPair, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()

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
	return &abstract.KeyPair{
		ID:         name,
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: priKey,
	}, nil
}

// GetKeyPair returns the key pair identified by id
func (s *Stack) GetKeyPair(id string) (*abstract.KeyPair, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()

	kp, err := keypairs.Get(s.ComputeClient, id).Extract()
	if err != nil {
		return nil, scerr.Wrap(err, fmt.Sprintf("error getting keypair"))
	}
	return &abstract.KeyPair{
		ID:         kp.Name,
		Name:       kp.Name,
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
	}, nil
}

// ListKeyPairs lists available key pairs
// Returned list can be empty
func (s *Stack) ListKeyPairs() ([]abstract.KeyPair, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "").WithStopwatch().Entering().OnExitTrace()()

	// Retrieve a pager (i.e. a paginated collection)
	pager := keypairs.List(s.ComputeClient)

	var kpList []abstract.KeyPair

	// Define an anonymous function to be executed on each page's iteration
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		keyList, err := keypairs.ExtractKeyPairs(page)
		if err != nil {
			return false, err
		}

		for _, kp := range keyList {
			kpList = append(kpList, abstract.KeyPair{
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
			return nil, scerr.Wrap(err, fmt.Sprintf("error listing keypairs"))
		}
	}
	return kpList, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (s *Stack) DeleteKeyPair(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", id).WithStopwatch().Entering().OnExitTrace()()

	err := keypairs.Delete(s.ComputeClient, id).ExtractErr()
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("error deleting key pair: %s", ProviderErrorToString(err)))
	}
	return nil
}

// toHostSize converts flavor attributes returned by OpenStack driver into abstract.HostEffectiveSizing
func (s *Stack) toHostSize(flavor map[string]interface{}) *abstract.HostEffectiveSizing {
	hostSizing := &abstract.HostEffectiveSizing{}
	if i, ok := flavor["id"]; ok {
		fid, ok := i.(string)
		if !ok {
			return nil
		}
		tpl, err := s.GetTemplate(fid)
		if err == nil {
			hostSizing.Cores = tpl.Cores
			hostSizing.DiskSize = tpl.DiskSize
			hostSizing.RAMSize = tpl.RAMSize
		} else {
			return nil
		}
	} else if _, ok := flavor["vcpus"]; ok {
		hostSizing.Cores = flavor["vcpus"].(int)
		hostSizing.DiskSize = flavor["disk"].(int)
		hostSizing.RAMSize = flavor["ram"].(float32) / 1000.0
	}
	return hostSizing
}

// toHostState converts host status returned by OpenStack driver into HostState enum
func toHostState(status string) hoststate.Enum {
	switch strings.ToLower(status) {
	case "build", "building":
		return hoststate.STARTING
	case "active":
		return hoststate.STARTED
	case "rescued":
		return hoststate.STOPPING
	case "stopped", "shutoff":
		return hoststate.STOPPED
	default:
		return hoststate.ERROR
	}
}

// InspectHost gathers host information from provider
func (s *Stack) InspectHost(hostParam interface{}) (*abstract.HostFull, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	var hostCore *abstract.HostCore
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, scerr.InvalidParameterError("hostParam", "cannot be an empty string")
		}
		hostCore = abstract.NewHostCore()
		hostCore.ID = hostParam
	case *abstract.HostCore:
		if hostParam == nil {
			return nil, scerr.InvalidParameterError("hostParam", "cannot be nil")
		}
		hostCore = hostParam
	default:
		return nil, scerr.InvalidParameterError("hostParam", "must be a non-empty string or a *abstract.Host")
	}
	hostRef := hostCore.Name
	if hostRef == "" {
		hostRef = hostCore.ID
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", hostRef).WithStopwatch().Entering().OnExitTrace()()

	server, err := s.queryServer(hostCore.ID)
	if err != nil {
		return nil, err
	}
	host, err := s.complementHost(hostCore, *server)
	if err != nil {
		return nil, err
	}

	if !host.OK() {
		logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(host))
	}

	return host, nil
}

func (s *Stack) queryServer(id string) (*servers.Server, error) {
	var (
		server   *servers.Server
		err      error
		notFound bool
	)

	timeout := 2 * temporal.GetBigDelay()
	retryErr := retry.WhileUnsuccessful(
		func() error {
			server, err = servers.Get(s.ComputeClient, id).Extract()
			if err != nil {
				switch err.(type) {
				case gophercloud.ErrDefault404:
					// If error is "resource not found", we want to return GopherCloud error as-is to be able
					// to behave differently in this special case. To do so, stop the retry
					notFound = true
					return nil
				case gophercloud.ErrDefault500:
					// When the response is "Internal Server Error", retries
					logrus.Warnf("received 'Internal Server Error', retrying servers.Get...")
					return err
				}
				// Any other error stops the retry
				err = scerr.NewError("error getting host '%s': %s", id, ProviderErrorToString(err))
				return nil
			}

			if server == nil {
				err = scerr.InconsistentError("error getting host, nil response from gophercloud")
				logrus.Debug(err)
				return err
			}

			lastState := toHostState(server.Status)
			if lastState != hoststate.ERROR && lastState != hoststate.STARTING {
				if lastState != hoststate.STARTED {
					logrus.Warnf("unexpected: host status of '%s' is '%s'", id, server.Status)
				}
				err = nil
				return nil
			}
			return scerr.NotAvailableError("server not ready yet")
		},
		temporal.GetMinDelay(),
		timeout,
	)
	if retryErr != nil {
		if _, ok := err.(retry.ErrTimeout); ok {
			return nil, abstract.ResourceTimeoutError("host", id, timeout)
		}
		return nil, retryErr
	}
	if err != nil {
		return nil, err
	}
	if notFound {
		return nil, abstract.ResourceNotFoundError("host", id)
	}

	if server == nil {
		return nil, abstract.ResourceNotFoundError("host", id)
	}

	return server, nil
}

// interpretAddresses converts adresses returned by the OpenStack driver
// Returns string slice containing the name of the networks, string map of IP addresses
// (indexed on network name), public ipv4 and ipv6 (if they exists)
func (s *Stack) interpretAddresses(
	addresses map[string]interface{},
) ([]string, map[ipversion.Enum]map[string]string, string, string, error) {
	var (
		networks    []string
		addrs       = map[ipversion.Enum]map[string]string{}
		AcccessIPv4 string
		AcccessIPv6 string
	)

	addrs[ipversion.IPv4] = map[string]string{}
	addrs[ipversion.IPv6] = map[string]string{}

	for n, obj := range addresses {
		networks = append(networks, n)
		for _, networkAddresses := range obj.([]interface{}) {
			address, ok := networkAddresses.(map[string]interface{})
			if !ok {
				return networks, addrs, AcccessIPv4, AcccessIPv6, scerr.InconsistentError("invalid network address")
			}
			version, ok := address["version"].(float64)
			if !ok {
				return networks, addrs, AcccessIPv4, AcccessIPv6, scerr.InconsistentError("invalid version")
			}
			fixedIP, ok := address["addr"].(string)
			if !ok {
				return networks, addrs, AcccessIPv4, AcccessIPv6, scerr.InconsistentError("invalid addr")
			}
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
					addrs[ipversion.IPv4][n] = fixedIP
				case 6:
					addrs[ipversion.IPv6][n] = fixedIP
				}
			}

		}
	}
	return networks, addrs, AcccessIPv4, AcccessIPv6, nil
}

// complementHost complements Host data with content of server parameter
func (s *Stack) complementHost(hostCore *abstract.HostCore, server servers.Server) (host *abstract.HostFull, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer scerr.OnPanic(&err)()

	networks, addresses, ipv4, ipv6, err := s.interpretAddresses(server.Addresses)
	if err != nil {
		return nil, err
	}

	// Updates intrinsic data of host if needed
	if hostCore.ID == "" {
		hostCore.ID = server.ID
	}
	if hostCore.Name == "" {
		hostCore.Name = server.Name
	}

	hostCore.LastState = toHostState(server.Status)
	if hostCore.LastState == hoststate.ERROR || hostCore.LastState == hoststate.STARTING {
		logrus.Warnf("[TRACE] Unexpected host's last state: %v", hostCore.LastState)
	}

	host = abstract.NewHostFull()
	host.Core = hostCore
	host.Description = &abstract.HostDescription{
		Created: server.Created,
		Updated: server.Updated,
	}

	host.Sizing = s.toHostSize(server.Flavor)

	var errors []error
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
			logrus.Debugf("failed to get data for network '%s'", netname)
			errors = append(errors, err)
			continue
		}
		networksByID[net.ID] = ""

		if ip, ok := addresses[ipversion.IPv4][netname]; ok {
			ipv4Addresses[net.ID] = ip
		} else {
			ipv4Addresses[net.ID] = ""
		}

		if ip, ok := addresses[ipversion.IPv6][netname]; ok {
			ipv6Addresses[net.ID] = ip
		} else {
			ipv6Addresses[net.ID] = ""
		}
	}

	// Updates network name and relationships if needed
	config := s.GetConfigurationOptions()
	networksByName := map[string]string{}
	for netid, netname := range networksByID {
		if netname == "" {
			net, err := s.GetNetwork(netid)
			if err != nil {
				switch err.(type) {
				case scerr.ErrNotFound:
					logrus.Errorf(err.Error())
					errors = append(errors, err)
				default:
					logrus.Errorf("failed to get network '%s': %v", netid, err)
					errors = append(errors, err)
				}
				continue
			}
			if net.Name == config.ProviderNetwork {
				continue
			}
			networksByID[netid] = net.Name
			networksByName[net.Name] = netid
		}
	}
	if len(errors) > 0 {
		return nil, scerr.ErrListError(errors)
	}
	host.Network = &abstract.HostNetwork{
		PublicIPv4:     ipv4,
		PublicIPv6:     ipv6,
		NetworksByID:   networksByID,
		NetworksByName: networksByName,
		IPv4Addresses:  ipv4Addresses,
		IPv6Addresses:  ipv6Addresses,
	}
	return host, nil
}

// GetHostByName returns the host using the name passed as parameter
// returns id of the host if found
// returns abstract.ErrResourceNotFound if not found
// returns abstract.ErrResourceNotAvailable if provider doesn't provide the id of the host in its response
func (s *Stack) GetHostByName(name string) (*abstract.HostCore, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "('%s')", name).WithStopwatch().Entering().OnExitTrace()()

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

// CreateHost creates an host satisfying request
func (s *Stack) CreateHost(request abstract.HostRequest) (host *abstract.HostFull, userData *userdata.Content, err error) {
	if s == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", request.ResourceName).WithStopwatch().Entering().OnExitTrace()()
	defer scerr.OnPanic(&err)()

	userData = userdata.NewContent()

	msgFail := "failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if request.DefaultGateway == nil && !request.PublicIP {
		return nil, userData, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without public IP or without attached network")
	}

	// The Default Network is the first of the provided list, by convention
	defaultNetwork := request.Networks[0]
	defaultNetworkID := defaultNetwork.ID
	defaultGateway := request.DefaultGateway
	isGateway := defaultGateway == nil && defaultNetwork.Name != abstract.SingleHostNetworkName
	defaultGatewayID := ""
	// defaultGatewayPrivateIP := ""
	if defaultGateway != nil {
		defaultGatewayID = defaultGateway.ID
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
			err = scerr.Wrap(err, "failed to create host UUID")
			logrus.Debugf(strprocess.Capitalize(err.Error()))
			return nil, userData, err
		}

		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
		request.KeyPair, err = s.CreateKeyPair(name)
		if err != nil {
			err = scerr.Wrap(err, "failed to create host key pair")
			logrus.Debugf(strprocess.Capitalize(err.Error()))
			return nil, userData, err
		}
	}
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, userData, scerr.Wrap(err, "failed to generate password")
		}
		request.Password = password
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	err = userData.Prepare(s.cfgOpts, request, defaultNetwork.CIDR, "")
	if err != nil {
		err = scerr.Wrap(err, "failed to prepare user data content")
		logrus.Debugf(strprocess.Capitalize(err.Error()))
		return nil, userData, err
	}

	template, err := s.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, userData, scerr.NewError("failed to get image: %s", ProviderErrorToString(err))
	}

	// Select usable availability zone, the first one in the list
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

	// --- Initializes abstract.HostCore ---

	hostCore := abstract.NewHostCore()
	hostCore.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition
	hostCore.Password = request.Password

	hostNetwork := &abstract.HostNetwork{}
	hostNetwork.DefaultNetworkID = defaultNetworkID
	hostNetwork.DefaultGatewayID = defaultGatewayID
	hostNetwork.DefaultGatewayPrivateIP = request.DefaultRouteIP
	hostNetwork.IsGateway = isGateway

	hostSizing := converters.HostTemplateToHostEffectiveSizing(template)

	// --- query provider for host creation ---

	logrus.Debugf("requesting host resource creation...")
	// Retry creation until success, for 10 minutes
	var server *servers.Server
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var inErr error
			server, inErr = servers.Create(s.ComputeClient, keypairs.CreateOptsExt{
				CreateOptsBuilder: srvOpts,
			}).Extract()
			if inErr != nil {
				if server != nil {
					servers.Delete(s.ComputeClient, server.ID)
				}
				msg := ProviderErrorToString(err)
				logrus.Warnf(msg)
				return fmt.Errorf(msg)
			}

			creationZone, zoneErr := s.GetAvailabilityZoneOfServer(server.ID)
			if zoneErr != nil {
				logrus.Tracef("Host successfully created but can't confirm AZ: %s", zoneErr)
			} else {
				logrus.Tracef("Host successfully created in requested AZ '%s'", creationZone)
				if creationZone != srvOpts.AvailabilityZone {
					if srvOpts.AvailabilityZone != "" {
						logrus.Warnf("Host created in the WRONG availability zone: requested '%s' and got instead '%s'", srvOpts.AvailabilityZone, creationZone)
					}
				}
			}

			if server == nil {
				return scerr.NewError("failed to create server")
			}
			hostCore.ID = server.ID
			hostCore.Name = server.Name

			// Wait that Host is ready, not just that the build is started
			hostCore, err = s.WaitHostReady(hostCore, temporal.GetHostTimeout())
			if err != nil {
				servers.Delete(s.ComputeClient, server.ID)
				msg := ProviderErrorToString(err)
				logrus.Warnf(msg)
				return fmt.Errorf(msg)
			}
			return nil
		},
		temporal.GetLongOperationTimeout(),
	)
	if retryErr != nil {
		return nil, userData, scerr.Wrap(retryErr, "error creating host")
	}
	newHost := abstract.NewHostFull()
	newHost.Core = hostCore
	newHost.Sizing = hostSizing
	newHost.Network = hostNetwork
	newHost.Description = &abstract.HostDescription{}

	logrus.Debugf("host resource created.")

	// Starting from here, delete host if exiting with error
	defer func() {
		if err != nil {
			logrus.Infof("Cleanup, deleting host '%s'", newHost.Core.Name)
			derr := s.DeleteHost(newHost.Core.ID)
			if derr != nil {
				switch derr.(type) {
				case scerr.ErrNotFound:
					logrus.Errorf("Cleaning up on failure, failed to delete host, resource not found: '%v'", derr)
				case scerr.ErrTimeout:
					logrus.Errorf("Cleaning up on failure, failed to delete host, timeout: '%v'", derr)
				default:
					logrus.Errorf("Cleaning up on failure, failed to delete host: '%v'", derr)
				}
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	newHost, err = s.complementHost(newHost.Core, *server)
	if err != nil {
		return nil, nil, err
	}

	// if Floating IP are used and public address is requested
	if s.cfgOpts.UseFloatingIP && request.PublicIP {
		// Create the floating IP
		ip, err := floatingips.Create(s.ComputeClient, floatingips.CreateOpts{
			Pool: s.authOpts.FloatingIPPool,
		}).Extract()
		if err != nil {
			return nil, userData, scerr.Wrap(err, fmt.Sprintf(msgFail, ProviderErrorToString(err)))
		}

		// Starting from here, delete Floating IP if exiting with error
		defer func() {
			if err != nil {
				logrus.Debugf("Cleanup, deleting floating ip '%s'", ip.ID)
				derr := floatingips.Delete(s.ComputeClient, ip.ID).ExtractErr()
				if derr != nil {
					logrus.Errorf("Error deleting Floating IP: %v", derr)
					err = scerr.AddConsequence(err, derr)
				}
			}
		}()

		// Associate floating IP to host
		err = floatingips.AssociateInstance(s.ComputeClient, newHost.Core.ID, floatingips.AssociateOpts{
			FloatingIP: ip.IP,
		}).ExtractErr()
		if err != nil {
			msg := fmt.Sprintf(msgFail, ProviderErrorToString(err))
			return nil, userData, scerr.Wrap(err, msg)
		}

		if ipversion.IPv4.Is(ip.IP) {
			newHost.Network.PublicIPv4 = ip.IP
		} else if ipversion.IPv6.Is(ip.IP) {
			newHost.Network.PublicIPv6 = ip.IP
		}
		userData.PublicIP = ip.IP
	}

	logrus.Infoln(msgSuccess)
	return newHost, userData, nil
}

// GetAvailabilityZoneOfServer retrieves the availability zone of server 'serverID'
func (s *Stack) GetAvailabilityZoneOfServer(serverID string) (string, error) {
	type ServerWithAZ struct {
		servers.Server
		az.ServerAvailabilityZoneExt
	}
	var allServers []ServerWithAZ
	allPages, err := servers.List(s.ComputeClient, nil).AllPages()
	if err != nil {
		return "", scerr.Wrap(err, "unable to retrieve servers")
	}
	err = servers.ExtractServersInto(allPages, &allServers)
	if err != nil {
		return "", scerr.Wrap(err, "unable to extract servers")
	}
	for _, server := range allServers {
		if server.ID == serverID {
			return server.AvailabilityZone, nil
		}
	}

	return "", scerr.NotFoundError("unable to find availability zone information for server '%s'", serverID)
}

// SelectedAvailabilityZone returns the selected availability zone
func (s *Stack) SelectedAvailabilityZone() (string, error) {
	if s == nil {
		return "", scerr.InvalidInstanceError()
	}

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
		logrus.Debugf("Selected Availability Zone: '%s'", s.selectedAvailabilityZone)
	}
	return s.selectedAvailabilityZone, nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s *Stack) WaitHostReady(hostParam interface{}, timeout time.Duration) (*abstract.HostCore, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	var host *abstract.HostCore
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, scerr.InvalidParameterError("hostParam", "cannot be empty string")
		}
		host = abstract.NewHostCore()
		host.ID = hostParam
	case *abstract.HostCore:
		if hostParam == nil {
			return nil, scerr.InvalidParameterError("hostParam", "canot be nil")
		}
		host = hostParam
	default:
		return nil, scerr.InvalidParameterError("hostParam", "must be a non-empty string or a *abstract.HostCore")
	}
	hostRef := host.Name
	if hostRef == "" {
		hostRef = host.ID
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", hostRef).WithStopwatch().Entering().OnExitTrace()()

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerErr := s.InspectHost(hostRef)
			if innerErr != nil {
				return innerErr
			}
			if hostTmp.Core.LastState == hoststate.ERROR {
				return retry.StopRetryError(nil, "host '%s' in error state", hostRef)
			}
			host = hostTmp.Core
			if host.LastState != hoststate.STARTED {
				return scerr.NotAvailableError("not in ready state (current state: %s)", host.LastState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return nil, abstract.ResourceNotAvailableError("host", "hostRef")
		case *retry.ErrTimeout:
			return host, abstract.ResourceTimeoutError("host", hostRef, timeout)
		}
		return host, retryErr
	}
	return host, nil
}

// GetHostState returns the current state of host identified by id
// hostParam can be a string or an instance of *abstract.HostCore; any other type will return an scerr.InvalidParameterError
func (s *Stack) GetHostState(hostParam interface{}) (hoststate.Enum, error) {
	if s == nil {
		return hoststate.ERROR, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, false, "").WithStopwatch().Entering().OnExitTrace()()

	host, err := s.InspectHost(hostParam)
	if err != nil {
		return hoststate.ERROR, err
	}
	return host.Core.LastState, nil
}

// ListHosts lists all hosts
func (s *Stack) ListHosts(details bool) (abstract.HostList, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "").WithStopwatch().Entering().OnExitTrace()()

	pager := servers.List(s.ComputeClient, servers.ListOpts{})
	hostList := abstract.HostList{}
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		list, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}

		for _, srv := range list {
			h := abstract.NewHostCore()
			h.ID = srv.ID
			var ah *abstract.HostFull
			if details {
				ah, err = s.complementHost(h, srv)
				if err != nil {
					return false, err
				}
			} else {
				ah = abstract.NewHostFull()
				ah.Core = h
			}
			hostList = append(hostList, ah)
		}
		return true, nil
	})
	if err != nil {
		return nil, scerr.Wrap(err, fmt.Sprintf("error listing hosts : %s", ProviderErrorToString(err)))
	}
	return hostList, nil
}

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to an host
func (s *Stack) getFloatingIP(hostID string) (*floatingips.FloatingIP, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
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
			return nil, scerr.Wrap(err, fmt.Sprintf("No floating IP found for host '%s': %s", hostID, ProviderErrorToString(err)))
		}
		return nil, scerr.Wrap(err, fmt.Sprintf("No floating IP found for host '%s'", hostID))

	}
	if len(fips) > 1 {
		return nil, scerr.Wrap(err, fmt.Sprintf("Configuration error, more than one Floating IP associated to host '%s'", hostID))
	}
	return &fips[0], nil
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s", id).WithStopwatch().Entering().OnExitTrace()()

	if s.cfgOpts.UseFloatingIP {
		fip, err := s.getFloatingIP(id)
		if err == nil {
			if fip != nil {
				err = floatingips.DisassociateInstance(s.ComputeClient, id, floatingips.DisassociateOpts{
					FloatingIP: fip.IP,
				}).ExtractErr()
				if err != nil {
					return scerr.Wrap(err, fmt.Sprintf("error deleting host '%s' : %s", id, ProviderErrorToString(err)))
				}
				err = floatingips.Delete(s.ComputeClient, fip.ID).ExtractErr()
				if err != nil {
					return scerr.Wrap(err, fmt.Sprintf("error deleting host '%s' : %s", id, ProviderErrorToString(err)))
				}
			}
		} else {
			return scerr.Wrap(err, fmt.Sprintf("error retrieving floating ip for '%s'", id))
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
				case gophercloud.ErrDefault404:
					// Resource not found, consider deletion successful
					logrus.Debugf("Host '%s' not found, deletion considered successful", id)
					return nil
				default:
					return scerr.NewError("failed to submit host '%s' deletion: %s", id, ProviderErrorToString(err))
				}
			}
			// 2nd, check host status every 5 seconds until check failed.
			// If check succeeds but state is Error, retry the deletion.
			// If check fails and error isn't 'resource not found', retry
			innerRetryErr := retry.WhileUnsuccessfulDelay5Seconds(
				func() error {
					host, err := servers.Get(s.ComputeClient, id).Extract()
					if err == nil {
						if toHostState(host.Status) == hoststate.ERROR {
							return nil
						}
						return scerr.NotAvailableError("host '%s' state is '%s'", host.Name, host.Status)
					}
					// FIXME: captures more error types
					switch err.(type) { // nolint
					case gophercloud.ErrDefault404:
						resourcePresent = false
						return nil
					}
					return err
				},
				temporal.GetContextTimeout(),
			)
			if innerRetryErr != nil {
				if _, ok := innerRetryErr.(retry.ErrTimeout); ok {
					// retry deletion...
					return abstract.ResourceTimeoutError("host", id, temporal.GetContextTimeout())
				}
				return innerRetryErr
			}
			if !resourcePresent {
				logrus.Debugf("Host '%s' not found, deletion considered successful after a few retries", id)
				return nil
			}
			return scerr.NotAvailableError("host '%s' in state 'ERROR', retrying to delete", id)
		},
		0,
		temporal.GetHostCleanupTimeout(),
	)
	if outerRetryErr != nil {
		return scerr.Wrap(outerRetryErr, fmt.Sprintf("error deleting host: retry error"))
	}
	return nil
}

// StopHost stops the host identified by id
func (s *Stack) StopHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", id).WithStopwatch().Entering().OnExitTrace()()

	err := startstop.Stop(s.ComputeClient, id).ExtractErr()
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("error stopping host : %s", ProviderErrorToString(err)))
	}
	return nil
}

// RebootHost reboots unconditionally the host identified by id
func (s *Stack) RebootHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", id).WithStopwatch().Entering().OnExitTrace()()

	// Try first a soft reboot, and if it fails (because host isn't in ACTIVE state), tries a hard reboot
	err := servers.Reboot(s.ComputeClient, id, servers.RebootOpts{Type: servers.SoftReboot}).ExtractErr()
	if err != nil {
		err = servers.Reboot(s.ComputeClient, id, servers.RebootOpts{Type: servers.HardReboot}).ExtractErr()
	}
	if err != nil {
		ftErr := scerr.NewError("error rebooting host '%s': %s", id, ProviderErrorToString(err))
		return scerr.Wrap(err, ftErr.Error())
	}
	return nil
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", id).WithStopwatch().Entering().OnExitTrace()()

	err := startstop.Start(s.ComputeClient, id).ExtractErr()
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("error starting host : %s", ProviderErrorToString(err)))
	}

	return nil
}

// ResizeHost ...
func (s *Stack) ResizeHost(id string, request abstract.HostSizingRequirements) (*abstract.HostFull, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.IfTrace("stack.compute"), "(%s)", id).WithStopwatch().Entering().OnExitTrace()()

	// TODO RESIZE Resize Host HERE
	logrus.Warn("Trying to resize a Host...")

	// TODO RESIZE Call this
	// servers.Resize()

	return nil, scerr.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}
