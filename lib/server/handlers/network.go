/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package handlers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hoststate"

	// "github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/NetworkState"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/networkproperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/abstract/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	safescaleutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers NetworkAPI

// TODO: At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// NetworkAPI defines API to manage networks
type NetworkAPI interface {
	Create(context.Context, string, string, ipversion.Enum, abstract.SizingRequirements, string, string, bool, string, bool) (*abstract.Network, error)
	List(context.Context, bool) ([]*abstract.Network, error)
	Inspect(context.Context, string) (*abstract.Network, error)
	Delete(context.Context, string) error
	Destroy(context.Context, string) error
}

// NetworkHandler an implementation of NetworkAPI
type NetworkHandler struct {
	service   iaas.Service
	ipVersion ipversion.Enum
}

// NewNetworkHandler Creates new Network service
func NewNetworkHandler(svc iaas.Service) NetworkAPI {
	return &NetworkHandler{
		service: svc,
	}
}

// Create creates a network
func (handler *NetworkHandler) Create(
	ctx context.Context,
	name string, cidr string, ipVersion ipversion.Enum,
	sizing abstract.SizingRequirements, theos string, gwname string,
	failover bool, domain string, keeponfailure bool,
) (network *abstract.Network, err error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be nil")
	}
	if failover && gwname != "" {
		return nil, fail.InvalidParameterError("gwname", "cannot be set if failover is set")
	}

	tracer := debug.NewTracer(
		nil,
		fmt.Sprintf(
			"('%s', '%s', %s, <sizing>, '%s', '%s', %v)", name, cidr, ipVersion.String(), theos, gwname, failover,
		),
		true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	type result struct {
		rhost *abstract.Network
		rerr  error
	}

	networkID := ""
	comm := make(chan result)

	defer func() {
		if network == nil && err == nil {
			logrus.Errorf("network is nil, should not without an error")
		}
	}()

	go func() {

		// Verify that the network doesn't exist first and manage by SafeScale
		_, err = metadata.LoadNetwork(handler.service, name)
		if err != nil {
			switch err.(type) {
			case fail.ErrNotFound:
				// so continue
			default:
				comm <- result{nil, err}
				return
			}
		} else {
			comm <- result{nil, fail.DuplicateError(fmt.Sprintf("network '%s' already exist", name))}
			return
		}

		if ctx.Err() != nil {
			comm <- result{nil, fail.AbortedError("operation already cancelled", ctx.Err())}
			return
		}

		// Check that the network doesn't exist outside SafeScale scope
		_, err = handler.service.GetNetworkByName(name)
		if err != nil {
			switch err.(type) {
			case fail.ErrNotFound:
			case fail.ErrInvalidRequest, fail.ErrTimeout:
				comm <- result{nil, err}
				return
			default:
				comm <- result{nil, err}
				return

			}
		} else {
			comm <- result{nil, fail.DuplicateError(fmt.Sprintf("network '%s' already exists (outside SafeScale scope)", name))}
			return
		}

		// Verify the CIDR is not routable
		routable, err := utils.IsCIDRRoutable(cidr)
		if err != nil {
			comm <- result{nil, fmt.Errorf("failed to determine if CIDR is not routable: %v", err)}
			return
		}
		if routable {
			comm <- result{nil, fmt.Errorf("cannot create such a network, CIDR must be not routable; please provide an appropriate CIDR (RFC1918)")}
			return
		}

		// Create the network
		logrus.Debugf("Creating network '%s' ...", name)
		network, err = handler.service.CreateNetwork(
			abstract.NetworkRequest{
				Name:      name,
				IPVersion: ipVersion,
				CIDR:      cidr,
				Domain:    domain,
			},
		)
		if err != nil {
			switch err.(type) {
			case fail.ErrNotFound, fail.ErrInvalidRequest, fail.ErrTimeout:
				comm <- result{nil, err}
				return
			default:
				comm <- result{nil, err}
				return
			}
		}
		network.Domain = domain

		newNetwork := network
		networkID = newNetwork.ID

		// Starting from here, delete network if exiting with error
		defer func() {
			if err != nil && keeponfailure {
				if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
					return
				}
			}
			if err != nil && !keeponfailure {
				if newNetwork != nil {
					derr := handler.service.DeleteNetwork(newNetwork.ID)
					if derr != nil {
						switch derr.(type) {
						case fail.ErrNotFound:
							logrus.Errorf("failed to delete network, resource not found: %+v", derr)
						case fail.ErrTimeout:
							logrus.Errorf("failed to delete network, timeout: %+v", derr)
						default:
							logrus.Errorf("failed to delete network, other reason: %+v", derr)
						}
						err = fail.AddConsequence(err, derr)
					}
				}
			}
		}()

		if ctx.Err() != nil {
			comm <- result{nil, fail.AbortedError("operation already cancelled", ctx.Err())}
			return
		}

		caps := handler.service.GetCapabilities()
		if failover && caps.PrivateVirtualIP {
			logrus.Infof("Provider support private Virtual IP, honoring the failover setup for gateways.")
		} else if failover && !caps.PrivateVirtualIP {
			logrus.Warningf("Provider doesn't support private Virtual IP, cannot set up high availability of network default route.")
			failover = false
		}

		// Creates VIP for gateways if asked for
		if failover {
			network.VIP, err = handler.service.CreateVIP(
				network.ID, fmt.Sprintf("for gateways of network %s", network.Name),
			)
			if err != nil {
				switch err.(type) {
				case fail.ErrNotFound, fail.ErrTimeout:
					comm <- result{nil, err}
					return
				default:
					comm <- result{nil, err}
					return
				}
			}

			// Starting from here, delete VIP if exists with error
			defer func() {
				if err != nil && keeponfailure {
					if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
						return
					}
				}
				if err != nil && !keeponfailure {
					if network != nil {
						derr := handler.service.DeleteVIP(network.VIP)
						if derr != nil {
							logrus.Errorf("failed to delete VIP: %+v", derr)
							err = fail.AddConsequence(err, derr)
						}
					}
				}
			}()
		}

		logrus.Debugf("Saving network metadata '%s' ...", network.Name)
		mn, err := metadata.SaveNetwork(handler.service, network)
		if err != nil {
			comm <- result{nil, err}
			return
		}

		// Starting from here, delete network metadata if exits with error
		defer func() {
			if err != nil && keeponfailure {
				if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
					return
				}
			}
			if err != nil && !keeponfailure {
				if mn != nil {
					derr := mn.Delete()
					if derr != nil {
						logrus.Errorf("failed to delete network metadata: %+v", derr)
						err = fail.AddConsequence(err, derr)
					}
				}
			}
		}()

		if ctx.Err() != nil {
			comm <- result{nil, fail.AbortedError("operation already cancelled", ctx.Err())}
			return
		}

		var template *abstract.HostTemplate
		tpls, err := handler.service.SelectTemplatesBySize(sizing, false)
		if err != nil {
			switch err.(type) {
			case fail.ErrNotFound, fail.ErrTimeout:
				comm <- result{nil, err}
				return
			default:
				comm <- result{nil, err}
				return
			}
		}
		if len(tpls) > 0 {
			template = tpls[0]
			msg := fmt.Sprintf(
				"Selected host template: '%s' (%d core%s", template.Name, template.Cores, utils.Plural(template.Cores),
			)
			if template.CPUFreq > 0 {
				msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
			}
			msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
			if template.GPUNumber > 0 {
				msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, utils.Plural(template.GPUNumber))
				if template.GPUType != "" {
					msg += fmt.Sprintf(" %s", template.GPUType)
				}
			}
			msg += ")"
			logrus.Infof(msg)
		} else {
			comm <- result{nil, fmt.Errorf("error creating network: no host template matching requirements for gateway")}
			return
		}
		img, err := handler.service.SearchImage(theos)
		if err != nil {
			switch err.(type) {
			case fail.ErrNotFound, fail.ErrTimeout:
				comm <- result{nil, err}
				return
			default:
				comm <- result{nil, err}
				return
			}
		}

		if ctx.Err() != nil {
			comm <- result{nil, fail.AbortedError("operation already cancelled", ctx.Err())}
			return
		}

		var primaryGatewayName, secondaryGatewayName string
		if failover || gwname == "" {
			primaryGatewayName = "gw-" + network.Name
		} else {
			primaryGatewayName = gwname
		}
		if failover {
			secondaryGatewayName = "gw2-" + network.Name
		}

		domain = strings.Trim(domain, ".")
		if domain != "" {
			domain = "." + domain
		}

		gwRequest := abstract.GatewayRequest{
			ImageID: img.ID,
			Network: network,
			// KeyPair:    keypair,
			OriginalOsRequest: theos,
			TemplateID:        template.ID,
			CIDR:              network.CIDR,
		}

		var (
			primaryGateway, secondaryGateway   *abstract.Host
			primaryUserdata, secondaryUserdata *userdata.Content
			secondaryTask                      concurrency.Task
			primaryMetadata, secondaryMetadata *metadata.Gateway
			secondaryErr                       error
			secondaryResult                    concurrency.TaskResult
		)

		// Starts primary gateway creation
		primaryRequest := gwRequest
		primaryRequest.Name = primaryGatewayName + domain
		primaryRequest.KeyPair, err = abstract.NewKeyPair(primaryRequest.Name)
		if err != nil {
			comm <- result{nil, err}
			return
		}
		primaryTask, err := concurrency.NewTaskWithContext(ctx)
		if err != nil {
			comm <- result{nil, err}
			return
		}
		primaryTask, err = primaryTask.Start(
			handler.createGateway, data.Map{
				"request": primaryRequest,
				"sizing":  sizing,
				"primary": true,
				"nokeep":  !keeponfailure,
			},
		)
		if err != nil {
			comm <- result{nil, err}
			return
		}

		if ctx.Err() != nil {
			comm <- result{nil, fail.AbortedError("operation already cancelled", ctx.Err())}
			return
		}

		// Starts secondary gateway creation if asked for
		if failover {
			secondaryRequest := gwRequest
			secondaryRequest.Name = secondaryGatewayName + domain
			secondaryRequest.KeyPair, err = abstract.NewKeyPair(secondaryRequest.Name)
			if err != nil {
				comm <- result{nil, err}
				return
			}
			secondaryTask, err = concurrency.NewTaskWithContext(ctx)
			if err != nil {
				comm <- result{nil, err}
				return
			}
			secondaryTask, err = secondaryTask.Start(
				handler.createGateway, data.Map{
					"request": secondaryRequest,
					"sizing":  sizing,
					"primary": false,
					"nokeep":  !keeponfailure,
				},
			)
			if err != nil {
				comm <- result{nil, err}
				return
			}
		}

		if ctx.Err() != nil {
			comm <- result{nil, fail.AbortedError("operation already cancelled", ctx.Err())}
			return
		}

		primaryResult, primaryErr := primaryTask.Wait()
		if primaryErr == nil {
			primaryGateway = primaryResult.(data.Map)["host"].(*abstract.Host)
			primaryUserdata = primaryResult.(data.Map)["userdata"].(*userdata.Content)
			if domain != "" {
				primaryUserdata.HostName = primaryGatewayName + domain
			}
			primaryMetadata = primaryResult.(data.Map)["metadata"].(*metadata.Gateway)

			// Starting from here, deletes the primary gateway if exiting with error
			defer func() {
				if err != nil && !keeponfailure {
					if keeponfailure {
						if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
							return
						}
					}
					derr := handler.deleteGateway(primaryGateway)
					if derr != nil {
						switch derr.(type) {
						case fail.ErrTimeout:
							logrus.Warnf("We should wait") // FIXME: Wait until gateway no longer exists
						default:
						}
						err = fail.AddConsequence(err, derr)
					}
					dmerr := handler.deleteGatewayMetadata(primaryMetadata)
					if dmerr != nil {
						switch dmerr.(type) {
						case fail.ErrTimeout:
							logrus.Warnf("We should wait") // FIXME: Wait until gateway no longer exists
						default:
						}
						err = fail.AddConsequence(err, dmerr)
					}
					if failover {
						failErr := handler.unbindHostFromVIP(newNetwork.VIP, primaryGateway)
						err = fail.AddConsequence(err, failErr)
					}
				}
			}()
		}
		if failover && secondaryTask != nil {
			secondaryResult, secondaryErr = secondaryTask.Wait()
			if secondaryErr == nil {
				secondaryGateway = secondaryResult.(data.Map)["host"].(*abstract.Host)
				secondaryUserdata = secondaryResult.(data.Map)["userdata"].(*userdata.Content)
				if domain != "" {
					secondaryUserdata.HostName = secondaryGatewayName + domain
				}
				secondaryMetadata = secondaryResult.(data.Map)["metadata"].(*metadata.Gateway)

				// Starting from here, deletes the secondary gateway if exiting with error
				defer func() {
					if err != nil && !keeponfailure {
						if keeponfailure {
							if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
								return
							}
						}
						derr := handler.deleteGateway(secondaryGateway)
						if derr != nil {
							switch derr.(type) {
							case fail.ErrTimeout:
								logrus.Warnf("We should wait") // FIXME: Wait until gateway no longer exists
							default:
							}
							err = fail.AddConsequence(err, derr)
						}
						dmerr := handler.deleteGatewayMetadata(secondaryMetadata)
						if dmerr != nil {
							switch dmerr.(type) {
							case fail.ErrTimeout:
								logrus.Warnf("We should wait") // FIXME: Wait until gateway no longer exists
							default:
							}
							err = fail.AddConsequence(err, dmerr)
						}
						failErr := handler.unbindHostFromVIP(newNetwork.VIP, secondaryGateway)
						err = fail.AddConsequence(err, failErr)
					}
				}()
			}
		}
		if primaryErr != nil {
			comm <- result{nil, primaryErr}
			return
		}
		if secondaryErr != nil {
			comm <- result{nil, secondaryErr}
			return
		}

		network.GatewayID = primaryGateway.ID
		if secondaryGateway != nil {
			network.SecondaryGatewayID = secondaryGateway.ID
		}
		err = mn.Write()
		if err != nil {
			comm <- result{nil, err}
			return
		}

		// Starts gateway(s) installation
		primaryTask, err = concurrency.NewTaskWithContext(ctx)
		if err != nil {
			comm <- result{nil, err}
			return
		}
		primaryTask, err = primaryTask.Start(handler.waitForInstallPhase1OnGateway, primaryGateway)
		if err != nil {
			comm <- result{nil, err}
			return
		}
		if failover && secondaryTask != nil {
			secondaryTask, err = concurrency.NewTaskWithContext(ctx)
			if err != nil {
				comm <- result{nil, err}
				return
			}

			secondaryTask, err = secondaryTask.Start(handler.waitForInstallPhase1OnGateway, secondaryGateway)
			if err != nil {
				comm <- result{nil, err}
				return
			}
		}

		var out interface{}
		var out2 interface{}

		out, primaryErr = primaryTask.Wait()
		if primaryErr != nil {
			comm <- result{nil, primaryErr}
			return
		}

		if outCast, ok := out.(string); ok {
			compareOsWithRequestedOs(outCast, theos)
		}

		if failover && secondaryTask != nil {
			out2, secondaryErr = secondaryTask.Wait()
			if secondaryErr != nil {
				comm <- result{nil, secondaryErr}
				return
			}

			if out2Cast, ok := out2.(string); ok {
				compareOsWithRequestedOs(out2Cast, theos)
			}
		}

		if primaryUserdata == nil {
			comm <- result{nil, fmt.Errorf("error creating network: primaryUserdata is nil")}
			return
		}

		// Complement userdata for gateway(s) with allocated IP
		primaryUserdata.PrimaryGatewayPrivateIP = primaryGateway.GetPrivateIP()
		primaryUserdata.PrimaryGatewayPublicIP = primaryGateway.GetPublicIP()
		if failover {
			keepalivedPassword, err := utils.GeneratePassword(16)
			if err != nil {
				comm <- result{nil, fmt.Errorf("error creating network: failed to generate keepalived password: %v", err)}
				return
			}
			primaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword

			primaryUserdata.SecondaryGatewayPrivateIP = secondaryGateway.GetPrivateIP()
			primaryUserdata.SecondaryGatewayPublicIP = secondaryGateway.GetPublicIP()

			if secondaryUserdata == nil {
				comm <- result{nil, fmt.Errorf("error creating network: secondaryUserdata is nil")}
				return
			}

			secondaryUserdata.PrimaryGatewayPrivateIP = primaryUserdata.PrimaryGatewayPrivateIP
			secondaryUserdata.PrimaryGatewayPublicIP = primaryUserdata.PrimaryGatewayPublicIP
			secondaryUserdata.SecondaryGatewayPrivateIP = primaryUserdata.SecondaryGatewayPrivateIP
			secondaryUserdata.SecondaryGatewayPublicIP = primaryUserdata.SecondaryGatewayPublicIP
			secondaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword
		}

		// Starts gateway(s) installation
		primaryTask, err = concurrency.NewTaskWithContext(ctx)
		if err != nil {
			comm <- result{nil, err}
			return
		}
		primaryTask, err = primaryTask.Start(
			handler.installPhase2OnGateway, data.Map{
				"host":     primaryGateway,
				"userdata": primaryUserdata,
			},
		)
		if err != nil {
			comm <- result{nil, err}
			return
		}
		if failover && secondaryTask != nil {
			secondaryTask, err = concurrency.NewTaskWithContext(ctx)
			if err != nil {
				comm <- result{nil, err}
				return
			}
			secondaryTask, err = secondaryTask.Start(
				handler.installPhase2OnGateway, data.Map{
					"host":     secondaryGateway,
					"userdata": secondaryUserdata,
				},
			)
			if err != nil {
				comm <- result{nil, err}
				return
			}
		}
		_, primaryErr = primaryTask.Wait()
		if primaryErr != nil {
			comm <- result{nil, primaryErr}
			return
		}
		if failover && secondaryTask != nil {
			_, secondaryErr = secondaryTask.Wait()
			if secondaryErr != nil {
				comm <- result{nil, secondaryErr}
				return
			}
		}

		comm <- result{newNetwork, nil}
		return
	}()

	select {
	case <-ctx.Done():
		err = fail.Errorf("network creation cancelled by safescale", ctx.Err())
		if networkID != "" {
			if keeponfailure {
				if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
					return
				}
			}
			retryErr := retryOnCommunicationFailure(
				func() error {
					if networkID != "" {
						nh, mhErr := metadata.LoadNetwork(handler.service, networkID)
						if mhErr != nil {
							if _, ok := mhErr.(fail.ErrNotFound); ok {
								return fail.AbortedError("not there", mhErr)
							}
							return mhErr
						}

						mhErr = nh.Delete()
						if mhErr != nil {
							if _, ok := mhErr.(fail.ErrNotFound); ok {
								return fail.AbortedError("not there", mhErr)
							}
							return mhErr
						}
					}
					return nil
				},
				0,
			)
			if retryErr != nil {
				switch retryErr.(type) {
				case fail.ErrNotFound:
					logrus.Errorf("failed to delete host '%s', resource not found: %v", networkID, retryErr)
				case fail.ErrTimeout:
					logrus.Errorf("failed to delete host '%s', timeout: %v", networkID, retryErr)
				default:
					logrus.Errorf("failed to delete host '%s', other reason: %v", networkID, retryErr)
				}
			}
		}
		if networkID != "" {
			if keeponfailure {
				if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
					return
				}
			}
			retryErr := retryOnCommunicationFailure(
				func() error {
					if networkID != "" {
						return handler.service.DeleteHost(networkID)
					}
					return nil
				},
				0,
			)
			if retryErr != nil {
				switch retryErr.(type) {
				case fail.ErrNotFound:
					logrus.Errorf("failed to delete host '%s', resource not found: %v", networkID, retryErr)
				case fail.ErrTimeout:
					logrus.Errorf("failed to delete host '%s', timeout: %v", networkID, retryErr)
				default:
					logrus.Errorf("failed to delete host '%s', other reason: %v", networkID, retryErr)
				}
			}
		}
		return nil, err
	case res := <-comm:
		return res.rhost, res.rerr
	}
}

func compareOsWithRequestedOs(theOs string, requestedOs string) {
	logrus.Debugf("Analysis of %s vs %s", theOs, requestedOs)
	frags := strings.Split(theOs, ",")
	if len(frags) < 3 {
		return
	}

	currentOs := fmt.Sprintf("%s %s", frags[2], frags[3])

	var err error

	verRequested := -1
	ver := -1

	osReqName := ""
	osName := ""

	if strings.Contains(requestedOs, " ") {
		fragments := strings.Split(requestedOs, " ")
		if len(fragments) >= 2 {
			osReqName = strings.ToUpper(fragments[0])
			version := fragments[1]

			verRequested, err = strconv.Atoi(version)
			if err != nil {
				return
			}
		} else {
			return
		}
	}

	if strings.Contains(currentOs, " ") {
		fragments := strings.Split(currentOs, " ")
		if len(fragments) >= 2 {
			osName = strings.ToUpper(fragments[0])
			version := fragments[1]

			ver, err = strconv.Atoi(version)
			if err != nil {
				return
			}
		} else {
			return
		}
	}

	if ver < verRequested {
		logrus.Warnf(
			"Requested OS version was (%d) and the OS version of the allocated machine (%d) is lower", verRequested, ver,
		)
	}

	if !strings.Contains(osReqName, osName) {
		logrus.Warnf("Requested OS (%s) doesn't seem to match obtained OS (%s)", osReqName, osName)
	}
}

func (handler *NetworkHandler) createGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		inputs data.Map
		ok     bool
	)
	if inputs, ok = params.(data.Map); !ok {
		return nil, fail.InvalidParameterError("params", "must be a data.Map")
	}
	// name := inputs["name"].(string)
	request := inputs["request"].(abstract.GatewayRequest)
	sizing := inputs["sizing"].(abstract.SizingRequirements)
	primary := inputs["primary"].(bool)
	nokeep := inputs["nokeep"].(bool)

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent", task.GetContext().Err())
	}

	// Check if gateway already exist in SafeScale scope
	_, err = metadata.LoadHost(handler.service, request.Name)
	if err != nil {
		switch err.(type) {
		case fail.ErrNotFound:
			// continue
		default:
			return nil, err
		}
	} else {
		return nil, fail.DuplicateError(fmt.Sprintf("host '%s' already exists", request.Name))
	}

	// Check if host exist outside SafeScale scope
	gw, err := handler.service.GetHostByName(request.Name)
	if err != nil {
		switch err.(type) {
		case fail.ErrNotFound:
			// continue
		case fail.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	} else {
		// gw in state 'TERMINATED' doesn't really exist, other states mean the gw exists
		if gw.LastState != hoststate.TERMINATED {
			return nil, abstract.ResourceDuplicateError("host", request.Name)
		}
	}

	logrus.Infof(
		"Requesting the creation of gateway '%s' using template '%s' with image '%s'", request.Name, request.TemplateID,
		request.ImageID,
	)
	gw, userData, err := handler.service.CreateGateway(request, &sizing)
	if err != nil {
		switch err.(type) {
		case fail.ErrNotFound, fail.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	// Starting from here, deletes the primary gateway if exiting with error
	defer func() {
		if err != nil && !nokeep {
			if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
				return
			}
		}
		if err != nil && nokeep {
			logrus.Warnf("Cleaning up on failure, deleting gateway '%s' host resource...", request.Name)
			derr := handler.service.DeleteHost(gw.ID)
			if derr != nil {
				msgRoot := "Cleaning up on failure, failed to delete gateway '%s'"
				switch derr.(type) {
				case fail.ErrNotFound:
					logrus.Errorf(msgRoot+", resource not found: %v", request.Name, derr)
				case fail.ErrTimeout:
					logrus.Errorf(msgRoot+", timeout: %v", request.Name, derr)
				default:
					logrus.Errorf(msgRoot+": %v", request.Name, derr)
				}
				err = fail.AddConsequence(err, derr)
			} else {
				logrus.Infof("Cleaning up on failure, gateway '%s' deleted", request.Name)
			}
			err = fail.AddConsequence(err, derr)
		}
	}()

	// Reloads the host to be sure all the properties are updated
	gw, err = handler.service.InspectHost(gw)
	if err != nil {
		switch err.(type) {
		case fail.ErrNotFound, fail.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	userData.UsesVIP = request.Network.VIP != nil

	// Binds gateway to VIP if primary
	if primary && request.Network.VIP != nil {
		err = handler.service.BindHostToVIP(request.Network.VIP, gw.ID)
		if err != nil {
			return nil, err
		}
		userData.PrivateVIP = request.Network.VIP.PrivateIP
		// userData.DefaultRouteIP = request.Network.VIP.PrivateIP
		userData.DefaultRouteIP = gw.GetPrivateIP()
		// userData.EndpointIP = request.Network.VIP.PublicIP
	} else {
		if request.Network.VIP != nil {
			userData.PrivateVIP = request.Network.VIP.PrivateIP
		}
		userData.DefaultRouteIP = gw.GetPrivateIP()
	}
	userData.IsPrimaryGateway = primary

	// Updates requested sizing in gateway property propsv1.HostSizing
	err = gw.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(clonable data.Clonable) error {
			gwSizingV1 := clonable.(*propsv1.HostSizing)
			gwSizingV1.RequestedSize = &propsv1.HostSize{
				Cores:     sizing.MinCores,
				RAMSize:   sizing.MinRAMSize,
				DiskSize:  sizing.MinDiskSize,
				GPUNumber: sizing.MinGPU,
				CPUFreq:   sizing.MinFreq,
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	// Writes Gateway metadata
	m, err := metadata.SaveGateway(handler.service, gw, request.Network.ID)
	if err != nil {
		return nil, err
	}
	result = data.Map{
		"host":     gw,
		"userdata": userData,
		"metadata": m,
	}
	return result, nil
}

func (handler *NetworkHandler) waitForInstallPhase1OnGateway(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	gw := params.(*abstract.Host)

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	logrus.Infof("Waiting until gateway '%s' is available by SSH ...", gw.Name)
	sshHandler := NewSSHHandler(handler.service)
	ssh, err := sshHandler.GetConfig(task.GetContext(), gw.ID)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("Provisioning gateway '%s', phase 1", gw.Name)

	var out string
	out, err = ssh.WaitServerReady("phase1", temporal.GetHostCreationTimeout())
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, err
		}
		if client.IsProvisioningError(err) {
			host, err := handler.service.GetHostByName(gw.Name)
			if err != nil {
				retrieveForensicsData(task.GetContext(), sshHandler, host)
			}

			return nil, fmt.Errorf(
				"error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH: [%+v]",
				gw.Name, err,
			)
		}
		return nil, err
	}

	logrus.Infof("SSH service of gateway '%s' started.", gw.Name)

	if out != "" {
		logrus.Infof("received output from phase 1: %s", out)
		return out, nil
	}

	return nil, nil
}

func (handler *NetworkHandler) installPhase2OnGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		gw       *abstract.Host
		userData *userdata.Content
		ok       bool
	)
	if gw, ok = params.(data.Map)["host"].(*abstract.Host); !ok {
		return nil, fail.InvalidParameterError("params", "missing field 'host'")
	}
	if userData, ok = params.(data.Map)["userdata"].(*userdata.Content); !ok {
		return nil, fail.InvalidParameterError("params", "missing field 'userdata'")
	}

	// Executes userdata phase2 script to finalize host installation
	tracer := debug.NewTracer(nil, fmt.Sprintf("(%s)", gw.Name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting configuration phase 2 on the gateway '%s'...", gw.Name),
		fmt.Sprintf("Ending configuration phase 2 on the gateway '%s'", gw.Name),
	)()

	if task == nil {
		return nil, fail.AbortedError("task cannot be nil", nil)
	}

	if task.Aborted() {
		return nil, fail.AbortedError("aborted by parent", task.GetContext().Err())
	}

	content, err := userData.Generate("phase2")
	if err != nil {
		return nil, err
	}
	pbHost, err := safescaleutils.ToPBHost(gw)
	if err != nil {
		return nil, err
	}
	err = install.UploadStringToRemoteFile(string(content), pbHost, utils.TempFolder+"/user_data.phase2.sh", "", "", "")
	if err != nil {
		return nil, err
	}

	command := fmt.Sprintf("sudo nohup bash %s/%s &", utils.TempFolder, "user_data.phase2.sh")
	sshHandler := NewSSHHandler(handler.service)

	ctx := task.GetContext()
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}

	returnCode, _, _, err := sshHandler.RunWithTimeout(ctx, gw.Name, command, outputs.COLLECT, 0)
	if err != nil {
		retrieveForensicsData(ctx, sshHandler, gw)

		return nil, err
	}
	if returnCode != 0 {
		retrieveForensicsData(ctx, sshHandler, gw)

		warnings, errs := getPhaseWarningsAndErrors(ctx, sshHandler, gw)

		return nil, fmt.Errorf(
			"failed to finalize gateway '%s' installation: errorcode '%d', warnings '%s', errors '%s'", gw.Name,
			returnCode, warnings, errs,
		)
	}

	// retrieve data anyway
	retrieveForensicsData(ctx, sshHandler, gw)

	logrus.Infof("Gateway '%s' successfully configured.", gw.Name)

	// Reboot gateway
	err = handler.service.RebootHost(gw.ID)
	if err != nil {
		return nil, err
	}

	ssh, err := sshHandler.GetConfig(ctx, gw.ID)
	if err != nil {
		return nil, err
	}

	sshDefaultTimeout := temporal.GetHostTimeout()
	_, err = ssh.WaitServerReady("ready", sshDefaultTimeout)
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, err
		}
		if client.IsProvisioningError(err) {
			logrus.Errorf("%+v", err)
			return nil, fmt.Errorf(
				"error creating network: Failure waiting for gateway '%s' to finish provisioning and being accessible through SSH",
				gw.Name,
			)
		}
		return nil, err
	}
	return nil, nil
}

func (handler *NetworkHandler) deleteGateway(gw *abstract.Host) (err error) {
	logrus.Warnf("Cleaning up on failure, deleting gateway '%s'...", gw.Name)
	err = handler.service.DeleteHost(gw.ID)
	if err != nil {
		switch err.(type) {
		case fail.ErrNotFound:
			logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s', resource not found: %v", gw.Name, err)
		case fail.ErrTimeout:
			logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s', timeout: %v", gw.Name, err)
		default:
			logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s': %v", gw.Name, err)
		}
	}
	logrus.Infof("Cleaning up on failure, gateway '%s' deleted", gw.Name)
	return err
}

func (handler *NetworkHandler) deleteGatewayMetadata(m *metadata.Gateway) (err error) {
	mm, err := m.Get()
	if err != nil {
		return err
	}
	name := mm.Name
	logrus.Warnf("Cleaning up on failure, deleting gateway '%s' metadata", name)
	derr := m.Delete()
	if derr != nil {
		logrus.Errorf("Cleaning up on failure, failed to delete gateway '%s' metadata: %+v", name, derr)
	}
	return derr
}

func (handler *NetworkHandler) unbindHostFromVIP(vip *abstract.VirtualIP, host *abstract.Host) (err error) {
	err = handler.service.UnbindHostFromVIP(vip, host.ID)
	if err != nil {
		switch err.(type) {
		case fail.ErrNotFound, fail.ErrTimeout:
			logrus.Debugf("Cleaning up on failure, failed to remove gateway bind from VIP: %v", err)
		default:
			logrus.Debugf("Cleaning up on failure, failed to remove gateway bind from VIP: %v", err)
		}
	} else {
		logrus.Infof("Cleaning up on failure, host '%s' bind removed from VIP", host.Name)
	}
	return err
}

// List returns the network list
func (handler *NetworkHandler) List(ctx context.Context, all bool) (netList []*abstract.Network, err error) {
	tracer := debug.NewTracer(nil, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if ctx != nil && ctx.Err() != nil {
		return nil, fail.AbortedError("aborted by parent", ctx.Err())
	}

	if all {
		return handler.service.ListNetworks()
	}

	mn, err := metadata.NewNetwork(handler.service)
	if err != nil {
		return nil, err
	}
	err = mn.Browse(
		func(network *abstract.Network) error {
			netList = append(netList, network)
			return nil
		},
	)

	if err != nil {
		return nil, err
	}

	return netList, err
}

// Inspect returns the network identified by ref, ref can be the name or the id
func (handler *NetworkHandler) Inspect(ctx context.Context, ref string) (network *abstract.Network, err error) {
	tracer := debug.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if ctx != nil && ctx.Err() != nil {
		return nil, fail.AbortedError("aborted by parent", ctx.Err())
	}

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		return nil, err
	}

	return mn.Get()
}

// Delete deletes network referenced by ref
func (handler *NetworkHandler) Delete(ctx context.Context, ref string) (err error) {
	tracer := debug.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if ctx != nil && ctx.Err() != nil {
		return fail.AbortedError("aborted by parent", ctx.Err())
	}

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); !ok {
			cleanErr := handler.service.DeleteNetwork(ref)
			if cleanErr != nil {
				switch cleanErr.(type) {
				case fail.ErrNotFound, fail.ErrTimeout:
					logrus.Warnf(
						"error deleting network on cleanup after failure to load metadata '%s': %v", ref, cleanErr,
					)
				default:
					logrus.Warnf(
						"error deleting network on cleanup after failure to load metadata '%s': %v", ref, cleanErr,
					)
				}
			}
			err = fail.AddConsequence(err, cleanErr)
		}
		return err
	}
	network, err := mn.Get()
	if err != nil {
		return err
	}

	// Check if hosts are still attached to network according to metadata
	var errorMsg string
	err = network.Properties.LockForRead(networkproperty.HostsV1).ThenUse(
		func(clonable data.Clonable) error {
			networkHostsV1 := clonable.(*propsv1.NetworkHosts)
			hostsLen := len(networkHostsV1.ByName)
			if hostsLen > 0 {
				list := make([]string, 0, hostsLen)
				for k := range networkHostsV1.ByName {
					rechost, err := handler.service.GetHostByName(k)
					if err == nil {
						if rechost.LastState != hoststate.TERMINATED {
							list = append(list, k)
						}
					}
				}
				if len(list) == 0 {
					return nil
				}
				verb := "are"
				if hostsLen == 1 {
					verb = "is"
				}
				errorMsg = fmt.Sprintf(
					"cannot delete network '%s': %d host%s %s still attached to it: %s",
					network.Name, hostsLen, utils.Plural(hostsLen), verb, strings.Join(list, ", "),
				)
				return abstract.ResourceNotAvailableError("network", network.Name)
			}
			return nil
		},
	)
	if err != nil {
		if _, ok := err.(fail.ErrNotAvailable); ok {
			return fmt.Errorf(errorMsg)
		}
		return err
	}

	// Delete gateway(s)
	if network.GatewayID != "" {
		mh, err := metadata.LoadHost(handler.service, network.GatewayID)
		if err != nil {
			logrus.Error(err)
		} else {
			if network.VIP != nil {
				mhm, merr := mh.Get()
				if merr != nil {
					return merr
				}
				err = handler.service.UnbindHostFromVIP(network.VIP, mhm.ID)
				if err != nil {
					logrus.Errorf("failed to unbind primary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.GatewayID) // allow no gateway, but log it
			if err != nil {
				switch err.(type) {
				case fail.ErrNotFound:
					logrus.Errorf(
						"failed to delete primary gateway, resource not found: %s", openstack.ProviderErrorToString(err),
					)
				case fail.ErrTimeout:
					logrus.Errorf("failed to delete primary gateway, timeout: %s", openstack.ProviderErrorToString(err))
				default:
					logrus.Errorf("failed to delete primary gateway: %s", openstack.ProviderErrorToString(err))
				}
			}

			err = mh.Delete()
			if err != nil {
				return err
			}
		}
	}
	if network.SecondaryGatewayID != "" {
		mh, err := metadata.LoadHost(handler.service, network.SecondaryGatewayID)
		if err != nil {
			logrus.Error(err)
		} else {
			if network.VIP != nil {
				err = handler.service.UnbindHostFromVIP(network.VIP, network.SecondaryGatewayID)
				if err != nil {
					logrus.Errorf("failed to unbind secondary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.SecondaryGatewayID) // allow no gateway, but log it
			if err != nil {
				switch err.(type) {
				case fail.ErrNotFound:
					logrus.Errorf(
						"failed to delete secondary gateway, resource not found: %s",
						openstack.ProviderErrorToString(err),
					)
				case fail.ErrTimeout:
					logrus.Errorf(
						"failed to delete secondary gateway, timeout: %s", openstack.ProviderErrorToString(err),
					)
				default:
					logrus.Errorf("failed to delete secondary gateway: %s", openstack.ProviderErrorToString(err))
				}
			}

			err = mh.Delete()
			if err != nil {
				return err
			}
		}
	}

	// Delete VIP if needed
	if network.VIP != nil {
		err = handler.service.DeleteVIP(network.VIP)
		if err != nil {
			logrus.Errorf("failed to delete VIP: %v", err)
		}
	}

	defer func() {
		if err != nil {
			// Delete metadata if there
			mnm, nerr := mn.Get()
			if nerr != nil {
				err = fail.AddConsequence(err, nerr)
			}
			if nerr == nil {
				if mnm != nil {
					derr := mn.Delete()
					if derr != nil {
						err = fail.AddConsequence(err, derr)
					}
				}
			}
		}
	}()

	waitMore := false
	// delete network, with tolerance
	err = handler.service.DeleteNetwork(network.ID)
	if err != nil {
		switch err.(type) {
		case fail.ErrNotFound:
			// If network doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
			logrus.Warnf("network not found on provider side, cleaning up metadata.")
			return err
		case fail.ErrTimeout:
			logrus.Error("cannot delete network due to a timeout")
			waitMore = true
		default:
			logrus.Error("cannot delete network, other reason")
		}
	}
	if waitMore {
		errWaitMore := retry.WhileUnsuccessfulDelay1Second(
			func() error {
				recNet, recErr := handler.service.GetNetwork(network.ID)
				if recNet != nil {
					return fmt.Errorf("still there")
				}
				if _, ok := recErr.(fail.ErrNotFound); ok {
					return nil
				}
				return fmt.Errorf("another kind of error")
			}, temporal.GetContextTimeout(),
		)
		if errWaitMore != nil {
			err = fail.AddConsequence(err, errWaitMore)
		}
	}

	if err != nil {
		return err
	}

	// Delete network metadata if there
	mnm, err := mn.Get()
	if err != nil {
		return err
	}

	if mnm != nil {
		err = mn.Delete()
		if err != nil {
			return err
		}
	}

	return nil
}

// Destroy destroys network referenced by ref
func (handler *NetworkHandler) Destroy(ctx context.Context, ref string) (err error) {
	tracer := debug.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if ctx != nil && ctx.Err() != nil {
		return fail.AbortedError("aborted by parent", ctx.Err())
	}

	mn, err := metadata.LoadNetwork(handler.service, ref)
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); !ok {
			cleanErr := handler.service.DeleteNetwork(ref)
			if cleanErr != nil {
				switch cleanErr.(type) {
				case fail.ErrNotFound, fail.ErrTimeout:
					logrus.Warnf(
						"error deleting network on cleanup after failure to load metadata '%s': %v", ref, cleanErr,
					)
				default:
					logrus.Warnf(
						"error deleting network on cleanup after failure to load metadata '%s': %v", ref, cleanErr,
					)
				}
			}
			err = fail.AddConsequence(err, cleanErr)
		}
		return err
	}
	network, err := mn.Get()
	if err != nil {
		return err
	}

	// Delete gateway(s)
	if network.GatewayID != "" {
		mh, err := metadata.LoadHost(handler.service, network.GatewayID)
		if err != nil {
			logrus.Error(err)
		} else {
			if network.VIP != nil {
				mhm, merr := mh.Get()
				if merr != nil {
					return merr
				}
				err = handler.service.UnbindHostFromVIP(network.VIP, mhm.ID)
				if err != nil {
					logrus.Errorf("failed to unbind primary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.GatewayID) // allow no gateway, but log it
			if err != nil {
				switch err.(type) {
				case fail.ErrNotFound:
					logrus.Errorf(
						"failed to delete primary gateway, resource not found: %s", openstack.ProviderErrorToString(err),
					)
				case fail.ErrTimeout:
					logrus.Errorf("failed to delete primary gateway, timeout: %s", openstack.ProviderErrorToString(err))
				default:
					logrus.Errorf("failed to delete primary gateway: %s", openstack.ProviderErrorToString(err))
				}
			}

			err = mh.Delete()
			if err != nil {
				return err
			}
		}
	}
	if network.SecondaryGatewayID != "" {
		mh, err := metadata.LoadHost(handler.service, network.SecondaryGatewayID)
		if err != nil {
			logrus.Error(err)
		} else {
			if network.VIP != nil {
				err = handler.service.UnbindHostFromVIP(network.VIP, network.SecondaryGatewayID)
				if err != nil {
					logrus.Errorf("failed to unbind secondary gateway from VIP: %v", err)
				}
			}

			err = handler.service.DeleteGateway(network.SecondaryGatewayID) // allow no gateway, but log it
			if err != nil {
				switch err.(type) {
				case fail.ErrNotFound:
					logrus.Errorf(
						"failed to delete secondary gateway, resource not found: %s",
						openstack.ProviderErrorToString(err),
					)
				case fail.ErrTimeout:
					logrus.Errorf(
						"failed to delete secondary gateway, timeout: %s", openstack.ProviderErrorToString(err),
					)
				default:
					logrus.Errorf("failed to delete secondary gateway: %s", openstack.ProviderErrorToString(err))
				}
			}

			err = mh.Delete()
			if err != nil {
				return err
			}
		}
	}

	// Delete VIP if needed
	if network.VIP != nil {
		err = handler.service.DeleteVIP(network.VIP)
		if err != nil {
			logrus.Errorf("failed to delete VIP: %v", err)
		}
	}

	defer func() {
		if err != nil {
			// Delete metadata if there
			mnm, nerr := mn.Get()
			if nerr != nil {
				err = fail.AddConsequence(err, nerr)
			}
			if nerr == nil {
				if mnm != nil {
					derr := mn.Delete()
					if derr != nil {
						err = fail.AddConsequence(err, derr)
					}
				}
			}
		}
	}()

	waitMore := false
	// delete network, with tolerance
	err = handler.service.DeleteNetwork(network.ID)
	if err != nil {
		switch err.(type) {
		case fail.ErrNotFound:
			// If network doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
			logrus.Warnf("network not found on provider side, cleaning up metadata.")
			return err
		case fail.ErrTimeout:
			logrus.Error("cannot delete network due to a timeout")
			waitMore = true
		default:
			logrus.Error("cannot delete network, other reason")
		}
	}
	if waitMore {
		errWaitMore := retry.WhileUnsuccessfulDelay1Second(
			func() error {
				recNet, recErr := handler.service.GetNetwork(network.ID)
				if recNet != nil {
					return fmt.Errorf("still there")
				}
				if _, ok := recErr.(fail.ErrNotFound); ok {
					return nil
				}
				return fmt.Errorf("another kind of error")
			}, temporal.GetContextTimeout(),
		)
		if errWaitMore != nil {
			err = fail.AddConsequence(err, errWaitMore)
		}
	}

	if err != nil {
		return err
	}

	// Delete network metadata if there
	mnm, err := mn.Get()
	if err != nil {
		return err
	}

	if mnm != nil {
		err = mn.Delete()
		if err != nil {
			return err
		}
	}

	return nil
}
