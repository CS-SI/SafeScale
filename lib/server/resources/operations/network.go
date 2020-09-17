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

package operations

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// networksFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
)

// network links Object Storage folder and Network
type network struct {
	*core
}

func nullNetwork() *network {
	return &network{core: nullCore()}
}

// NewNetwork creates an instance of Network
func NewNetwork(svc iaas.Service) (resources.Network, fail.Error) {
	if svc.IsNull() {
		return nullNetwork(), fail.InvalidParameterError("svc", "cannot be null value")
	}

	coreInstance, xerr := newCore(svc, "network", networksFolderName, &abstract.Network{})
	if xerr != nil {
		return nullNetwork(), xerr
	}

	return &network{core: coreInstance}, nil
}

// LoadNetwork loads the metadata of a network
func LoadNetwork(task concurrency.Task, svc iaas.Service, ref string) (resources.Network, fail.Error) {
	if task.IsNull() {
		return nullNetwork(), fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc.IsNull() {
		return nullNetwork(), fail.InvalidParameterError("svc", "cannot be null value")
	}
	if ref == "" {
		return nullNetwork(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	objn, xerr := NewNetwork(svc)
	if xerr != nil {
		return nullNetwork(), xerr
	}
	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return objn.Read(task, ref)
		},
		10*time.Second, // FIXME: parameterize
	)
	if xerr != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := xerr.(*retry.ErrTimeout); ok {
			logrus.Debugf("timeout reading metadata of network '%s'", ref)
			xerr = fail.NotFoundError("network '%s' not found: %s", ref, fail.RootCause(xerr).Error())
		}
		return nullNetwork(), xerr
	}
	return objn, nil
}

// IsNull tells if the instance corresponds to network Null Value
func (rn *network) IsNull() bool {
	return rn == nil || rn.core.IsNull()
}

// Create creates a network
func (rn *network) Create(task concurrency.Task, req abstract.NetworkRequest, gwname string, gwSizing *abstract.HostSizingRequirements) (xerr fail.Error) {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(
		task,
		true,
		"('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.Image, req.HA,
	).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	// Check if network already exists and is managed by SafeScale
	svc := rn.GetService()
	if _, xerr = LoadNetwork(task, svc, req.Name); xerr == nil {
		return fail.DuplicateError("network '%s' already exists", req.Name)
	}

	// Verify if the network already exist and in this case is not managed by SafeScale
	if _, xerr = svc.InspectNetworkByName(req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		case *fail.ErrInvalidRequest, *fail.ErrTimeout:
			return xerr
		default:
			return xerr
		}
	} else {
		return fail.DuplicateError("network '%s' already exists (not managed by SafeScale)", req.Name)
	}

	// Verify the CIDR is not routable
	if req.CIDR != "" {
		routable, xerr := net.IsCIDRRoutable(req.CIDR)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to determine if CIDR is not routable")
		}
		if routable {
			return fail.InvalidRequestError("cannot create such a network, CIDR must not be routable; please choose an appropriate CIDR (RFC1918)")
		}
	}

	// Create the network
	logrus.Debugf("Creating network '%s' ...", req.Name)
	an, xerr := svc.CreateNetwork(req)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound, *fail.ErrInvalidRequest, *fail.ErrTimeout:
			return xerr
		default:
			return xerr
		}
	}

	// Starting from here, delete network if exiting with error
	defer func() {
		if xerr != nil && an != nil && !req.KeepOnFailure {
			derr := svc.DeleteNetwork(an.ID)
			if derr != nil {
				switch derr.(type) {
				case *fail.ErrNotFound:
					logrus.Errorf("failed to delete network: resource not found: %+v", derr)
				case *fail.ErrTimeout:
					logrus.Errorf("failed to delete network: timeout: %+v", derr)
				default:
					logrus.Errorf("failed to delete network: %+v", derr)
				}
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	caps := svc.GetCapabilities()
	failover := req.HA
	if failover {
		if caps.PrivateVirtualIP {
			logrus.Info("Provider support private Virtual IP, honoring the failover setup for gateways.")
		} else {
			logrus.Warning("Provider doesn't support private Virtual IP, cannot set up high availability of network default route.")
			failover = false
		}
	}

	// Creates VIP for gateways if asked for
	if failover {
		if an.VIP, xerr = svc.CreateVIP(an.ID, fmt.Sprintf("for gateways of network %s", an.Name)); xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound, *fail.ErrTimeout:
				return xerr
			default:
				return xerr
			}
		}

		// Starting from here, delete VIP if exists with error
		defer func() {
			if xerr != nil && !req.KeepOnFailure {
				if an != nil {
					derr := svc.DeleteVIP(an.VIP)
					if derr != nil {
						logrus.Errorf("failed to delete VIP: %+v", derr)
						_ = xerr.AddConsequence(derr)
					}
				}
			}
		}()
	}

	// Write network object metadata
	// logrus.Debugf("Saving network metadata '%s' ...", network.GetName)
	if xerr = rn.Carry(task, an); xerr != nil {
		return xerr
	}

	// Starting from here, delete network metadata if exits with error
	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			derr := rn.core.Delete(task)
			if derr != nil {
				logrus.Errorf("failed to delete network metadata: %+v", derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	xerr = rn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		an.NetworkState = networkstate.GATEWAY_CREATION
		return nil
	})
	if xerr != nil {
		return xerr
	}

	var template *abstract.HostTemplate
	tpls, xerr := svc.SelectTemplatesBySize(*gwSizing, false)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to find appropriate template")
	}
	if len(tpls) > 0 {
		template = tpls[0]
		msg := fmt.Sprintf("Selected host template: '%s' (%d core%s", template.Name, template.Cores, strprocess.Plural(uint(template.Cores)))
		if template.CPUFreq > 0 {
			msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
		}
		msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
		if template.GPUNumber > 0 {
			msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, strprocess.Plural(uint(template.GPUNumber)))
			if template.GPUType != "" {
				msg += fmt.Sprintf(" %s", template.GPUType)
			}
		}
		msg += ")"
		logrus.Infof(msg)
	} else {
		return fail.NotFoundError("error creating network: no host template matching requirements for gateway")
	}
	if req.Image == "" {
		// if gwSizing.Image != "" {
		req.Image = gwSizing.Image
		// }
	}
	if req.Image == "" {
		cfg, xerr := svc.GetConfigurationOptions()
		if xerr != nil {
			return xerr
		}
		req.Image = cfg.GetString("DefaultImage")
		gwSizing.Image = req.Image
	}
	img, xerr := svc.SearchImage(req.Image)
	if xerr != nil {
		return fail.Wrap(xerr, "unable to create network gateway")
	}

	networkName := rn.GetName()
	var primaryGatewayName, secondaryGatewayName string
	if failover || gwname == "" {
		primaryGatewayName = "gw-" + networkName
	} else {
		primaryGatewayName = gwname
	}
	if failover {
		secondaryGatewayName = "gw2-" + networkName
	}

	domain := strings.Trim(req.Domain, ".")
	if domain != "" {
		domain = "." + domain
	}

	keypairName := "kp_" + networkName
	keypair, xerr := svc.CreateKeyPair(keypairName)
	if xerr != nil {
		return xerr
	}

	keepalivedPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return fail.ToError(err)
	}

	gwRequest := abstract.HostRequest{
		ImageID:       img.ID,
		Networks:      []*abstract.Network{an},
		KeyPair:       keypair,
		TemplateID:    template.ID,
		KeepOnFailure: req.KeepOnFailure,
	}

	var (
		primaryGateway, secondaryGateway   *host
		primaryUserdata, secondaryUserdata *userdata.Content
		primaryTask, secondaryTask         concurrency.Task
		secondaryErr                       fail.Error
		secondaryResult                    concurrency.TaskResult
	)

	// Starts primary gateway creation
	primaryRequest := gwRequest
	primaryRequest.ResourceName = primaryGatewayName
	primaryRequest.HostName = primaryGatewayName + domain
	primaryTask, xerr = task.StartInSubtask(rn.taskCreateGateway, data.Map{
		"request": primaryRequest,
		"sizing":  *gwSizing,
		"primary": true,
	})
	if xerr != nil {
		return xerr
	}

	// Starts secondary gateway creation if asked for
	if failover {
		secondaryRequest := gwRequest
		secondaryRequest.ResourceName = secondaryGatewayName
		secondaryRequest.HostName = secondaryGatewayName
		if req.Domain != "" {
			secondaryRequest.HostName = secondaryGatewayName + domain
		}
		secondaryTask, xerr = task.StartInSubtask(rn.taskCreateGateway, data.Map{
			"request": secondaryRequest,
			"sizing":  *gwSizing,
			"primary": false,
		})
		if xerr != nil {
			return xerr
		}
	}

	primaryResult, primaryErr := primaryTask.Wait()
	if primaryErr == nil {
		result, ok := primaryResult.(data.Map)
		if !ok {
			return fail.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(primaryResult).String())
		}
		primaryGateway = result["host"].(*host)
		primaryUserdata = result["userdata"].(*userdata.Content)
		primaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword

		// Starting from here, deletes the primary gateway if exiting with error
		defer func() {
			if xerr != nil && !req.KeepOnFailure {
				logrus.Debugf("Cleaning up on failure, deleting gateway '%s'...", primaryGateway.GetName())
				derr := rn.deleteGateway(task, primaryGateway)
				if derr != nil {
					switch derr.(type) {
					case *fail.ErrTimeout:
						logrus.Warnf("We should wait") // FIXME: Wait until gateway no longer exists
					default:
					}
					_ = xerr.AddConsequence(derr)
				} else {
					logrus.Infof("Cleaning up on failure, gateway '%s' deleted", primaryGateway.GetName())
				}
				if failover {
					failErr := rn.unbindHostFromVIP(task, an.VIP, primaryGateway)
					_ = xerr.AddConsequence(failErr)
				}
			}
		}()
	}
	if failover && secondaryTask != nil {
		secondaryResult, secondaryErr = secondaryTask.Wait()
		if secondaryErr == nil {
			result, ok := secondaryResult.(data.Map)
			if !ok {
				return fail.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(secondaryResult).String())
			}

			secondaryGateway = result["host"].(*host)
			secondaryUserdata = result["userdata"].(*userdata.Content)
			secondaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword

			// Starting from here, deletes the secondary gateway if exiting with error
			defer func() {
				if xerr != nil && !req.KeepOnFailure {
					derr := rn.deleteGateway(task, secondaryGateway)
					if derr != nil {
						switch derr.(type) {
						case *fail.ErrTimeout:
							logrus.Warnf("We should wait") // FIXME Wait until gateway no longer exists
						default:
						}
						_ = xerr.AddConsequence(derr)
					}
					failErr := rn.unbindHostFromVIP(task, an.VIP, secondaryGateway)
					if failErr != nil {
						_ = xerr.AddConsequence(failErr)
					}
				}
			}()
		}
	}
	if primaryErr != nil {
		return fail.Wrap(primaryErr, "failed to create gateway '%s'", primaryGatewayName)
	}
	if secondaryErr != nil {
		return fail.Wrap(secondaryErr, "failed to create gateway '%s'", secondaryGatewayName)
	}

	// Update metadata of network object
	xerr = rn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// an.GatewayID = primaryGateway.GetID()
		primaryUserdata.PrimaryGatewayPrivateIP = primaryGateway.getPrivateIP(task)
		primaryUserdata.PrimaryGatewayPublicIP = primaryGateway.getPublicIP(task)
		primaryUserdata.IsPrimaryGateway = true
		if an.VIP != nil {
			primaryUserdata.DefaultRouteIP = an.VIP.PrivateIP
			primaryUserdata.EndpointIP = an.VIP.PublicIP
		} else {
			primaryUserdata.DefaultRouteIP = primaryUserdata.PrimaryGatewayPrivateIP
			primaryUserdata.EndpointIP = primaryUserdata.PrimaryGatewayPublicIP
		}
		if secondaryGateway != nil {
			// an.SecondaryGatewayID = secondaryGateway.GetID()
			primaryUserdata.SecondaryGatewayPrivateIP = secondaryGateway.getPrivateIP(task)
			secondaryUserdata.PrimaryGatewayPrivateIP = primaryUserdata.PrimaryGatewayPrivateIP
			secondaryUserdata.SecondaryGatewayPrivateIP = primaryUserdata.SecondaryGatewayPrivateIP
			primaryUserdata.SecondaryGatewayPublicIP = secondaryGateway.getPublicIP(task)
			secondaryUserdata.PrimaryGatewayPublicIP = primaryUserdata.PrimaryGatewayPublicIP
			secondaryUserdata.SecondaryGatewayPublicIP = primaryUserdata.SecondaryGatewayPublicIP
			secondaryUserdata.IsPrimaryGateway = false
		}

		return nil
	})
	if xerr != nil {
		return xerr
	}

	// As hosts are gateways, the configuration stopped on phase 'netsec', the remaining phases 'hwga', 'sysfix' and 'final' have to be run
	if primaryTask, xerr = concurrency.NewTask(); xerr != nil {
		return xerr
	}
	xerr = rn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		an.NetworkState = networkstate.GATEWAY_CONFIGURATION
		return nil
	})
	if xerr != nil {
		return xerr
	}

	primaryTask, xerr = primaryTask.Start(rn.taskFinalizeGatewayConfiguration, data.Map{
		"host":     primaryGateway,
		"userdata": primaryUserdata,
	})
	if xerr != nil {
		return xerr
	}
	if failover && secondaryTask != nil {
		if secondaryTask, xerr = concurrency.NewTask(); xerr != nil {
			return xerr
		}
		secondaryTask, xerr = secondaryTask.Start(rn.taskFinalizeGatewayConfiguration, data.Map{
			"host":     secondaryGateway,
			"userdata": secondaryUserdata,
		})
		if xerr != nil {
			return xerr
		}
	}
	if _, primaryErr = primaryTask.Wait(); primaryErr != nil {
		return primaryErr
	}
	if failover && secondaryTask != nil {
		if _, secondaryErr = secondaryTask.Wait(); secondaryErr != nil {
			return secondaryErr
		}
	}

	// Updates network state in metadata
	// logrus.Debugf("Updating network metadata '%s' ...", network.GetName)
	return rn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		an.NetworkState = networkstate.READY
		return nil
	})
}

// deleteGateway eases a gateway deletion
// Note: doesn't use gw.Remove() because by rule a Delete on a gateway is not permitted
func (rn network) deleteGateway(task concurrency.Task, gw resources.Host) (xerr fail.Error) {
	name := gw.GetName()
	fail.OnExitLogError(&xerr, "failed to delete gateway '%s'", name)

	var errors []error
	if xerr = rn.GetService().DeleteHost(gw.GetID()); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound: // host resource not found, considered as a success.
			break
		case *fail.ErrTimeout:
			errors = append(errors, fail.Wrap(xerr, "failed to delete host '%s', timeout", name))
		default:
			errors = append(errors, fail.Wrap(xerr, "failed to delete host '%s'", name))
		}
	}
	if xerr = gw.(*host).core.Delete(task); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound: // host metadata not found, considered as a success.
			break
		case *fail.ErrTimeout:
			errors = append(errors, fail.Wrap(xerr, "timeout trying to delete gateway metadata", name))
		default:
			errors = append(errors, fail.Wrap(xerr, "failed to delete gateway '%s' metadata", name))
		}
	}
	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}
	return nil
}

func (rn network) unbindHostFromVIP(task concurrency.Task, vip *abstract.VirtualIP, host resources.Host) fail.Error {
	name := host.GetName()
	if xerr := rn.GetService().UnbindHostFromVIP(vip, host.GetID()); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound, *fail.ErrTimeout:
			logrus.Debugf("Cleaning up on failure, failed to remove '%s' gateway bind from VIP: %v", name, xerr)
		default:
			logrus.Debugf("Cleaning up on failure, failed to remove '%s' gateway bind from VIP: %v", name, xerr)
		}
		return xerr
	}
	logrus.Infof("Cleaning up on failure, host '%s' bind removed from VIP", name)
	return nil
}

// Browse walks through all the metadata objects in network
func (rn network) Browse(task concurrency.Task, callback func(*abstract.Network) fail.Error) fail.Error {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "can't be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "can't be nil")
	}

	return rn.core.BrowseFolder(task, func(buf []byte) fail.Error {
		an := abstract.NewNetwork()
		xerr := an.Deserialize(buf)
		if xerr != nil {
			return xerr
		}
		return callback(an)
	})
}

// AttachHost links host GetID to the network
func (rn *network) BindHost(task concurrency.Task, host resources.Host) (xerr fail.Error) {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return fail.InvalidParameterError("host", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, true, "("+host.GetName()+")").Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	hostID := host.GetID()
	hostName := host.GetName()

	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			networkHostsV1.ByID[hostID] = hostName
			networkHostsV1.ByName[hostName] = hostID
			return nil
		})
	})
}

// DetachHost unlinks host GetID from network
func (rn *network) UnbindHost(task concurrency.Task, hostID string) (xerr fail.Error) {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, true, "('"+hostID+"')").Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	return rn.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostName, found := networkHostsV1.ByID[hostID]
			if found {
				delete(networkHostsV1.ByName, hostName)
				delete(networkHostsV1.ByID, hostID)
			}
			return nil
		})
	})
}

// ListHosts returns the list of Host attached to the network (excluding gateway)
func (rn network) ListHosts(task concurrency.Task) (_ []resources.Host, xerr fail.Error) {
	if rn.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	defer debug.NewTracer(task, tracing.ShouldTrace("resources.network")).Entering().Exiting()
	defer fail.OnExitLogError(&xerr, "error listing hosts")
	defer fail.OnPanic(&xerr)

	var list []resources.Host
	xerr = rn.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			svc := rn.GetService()
			for id := range networkHostsV1.ByID {
				host, innerErr := LoadHost(task, svc, id)
				if innerErr != nil {
					return innerErr
				}
				list = append(list, host)
			}
			return nil
		})
	})
	return list, xerr
}

// GetGateway returns the gateway related to network
func (rn network) GetGateway(task concurrency.Task, primary bool) (_ resources.Host, xerr fail.Error) {
	if rn.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	defer fail.OnPanic(&xerr)

	primaryStr := "primary"
	if !primary {
		primaryStr = "secondary"
	}
	tracer := debug.NewTracer(nil, true, "(%s)", primaryStr).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	var gatewayID string
	xerr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if primary {
			gatewayID = an.GatewayID
		} else {
			gatewayID = an.SecondaryGatewayID
		}
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}
	if gatewayID == "" {
		return nil, fail.NotFoundError("no %s gateway GetID found in network properties", primaryStr)
	}
	return LoadHost(task, rn.GetService(), gatewayID)
}

// getGateway returns a resources.Host corresponding to the gateway requested. May return HostNull if no gateway exists.
func (rn network) getGateway(task concurrency.Task, primary bool) resources.Host {
	host, _ := rn.GetGateway(task, primary)
	return host
}

// Delete deletes network referenced by ref
func (rn *network) Delete(task concurrency.Task) (xerr fail.Error) {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	rn.SafeLock(task)
	defer rn.SafeUnlock(task)

	// var gwID string
	xerr = rn.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		svc := rn.GetService()

		// Check if hosts are still attached to network according to metadata
		var errorMsg string
		innerErr := props.Inspect(task, networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostsLen := uint(len(networkHostsV1.ByName))
			if hostsLen > 0 {
				list := make([]string, 0, hostsLen)
				for k := range networkHostsV1.ByName {
					list = append(list, k)
				}
				verb := "are"
				if hostsLen == 1 {
					verb = "is"
				}
				errorMsg = fmt.Sprintf("cannot delete network '%s': %d host%s %s still attached to it: %s",
					an.Name, hostsLen, strprocess.Plural(hostsLen), verb, strings.Join(list, ", "))
				return fail.NotAvailableError(errorMsg)
			}
			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		// Leave a chance to abort
		taskStatus, _ := task.GetStatus()
		if taskStatus == concurrency.ABORTED {
			return fail.AbortedError(nil)
		}

		// 1st delete primary gateway
		if an.GatewayID != "" {
			stop := false
			rh, innerErr := LoadHost(task, svc, an.GatewayID)
			if innerErr != nil {
				if _, ok := innerErr.(*fail.ErrNotFound); !ok {
					return innerErr
				}
				stop = true
			}
			if !stop {
				if rh != nil {
					logrus.Debugf("Deleting gateway '%s'...", rh.GetName())
					innerErr = rn.deleteGateway(task, rh)
					if _, ok := innerErr.(*fail.ErrNotFound); ok { // allow no gateway, but log it
						logrus.Errorf("Failed to delete primary gateway: %s", innerErr.Error())
					} else if innerErr != nil {
						return innerErr
					}
				}
			} else {
				logrus.Infof("Primary getGateway of network '%s' appears to be already deleted", an.Name)
			}
		}

		// 2nd delete secondary gateway
		if an.SecondaryGatewayID != "" {
			stop := false
			rh, innerErr := LoadHost(task, svc, an.SecondaryGatewayID)
			if innerErr != nil {
				if _, ok := innerErr.(*fail.ErrNotFound); !ok {
					return innerErr
				}
				stop = true
			}
			if !stop {
				if rh != nil {
					logrus.Debugf("Deleting gateway '%s'...", rh.GetName())
					innerErr = rn.deleteGateway(task, rh)
					if innerErr != nil { // allow no gateway, but log it
						if _, ok := innerErr.(*fail.ErrNotFound); ok { // nolint
							logrus.Errorf("failed to delete secondary gateway: %s", innerErr.Error())
						} else {
							return innerErr
						}
					}
				}
			} else {
				logrus.Infof("Secondary getGateway of network '%s' appears to be already deleted", an.Name)
			}
		}

		// 3rd delete VIP if needed
		if an.VIP != nil {
			innerErr = svc.DeleteVIP(an.VIP)
			if innerErr != nil {
				// FIXME: THINK Should we exit on failure ?
				logrus.Errorf("failed to delete VIP: %v", innerErr)
			}
		}

		waitMore := false
		// delete network, with tolerance
		innerErr = svc.DeleteNetwork(an.ID)
		if innerErr != nil {
			switch innerErr.(type) {
			case *fail.ErrNotFound:
				// If network doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
				logrus.Warnf("network not found on provider side, cleaning up metadata.")
				return innerErr
			case *fail.ErrTimeout:
				logrus.Error("cannot delete network due to a timeout")
				waitMore = true
			default:
				logrus.Error("cannot delete network, other reason")
			}
		}
		if waitMore {
			errWaitMore := retry.WhileUnsuccessfulDelay1Second(
				func() error {
					recNet, recErr := svc.InspectNetwork(an.ID)
					if recNet != nil {
						return fmt.Errorf("still there")
					}
					if _, ok := recErr.(*fail.ErrNotFound); ok {
						return nil
					}
					return fail.Wrap(recErr, "another kind of error")
				},
				temporal.GetContextTimeout(),
			)
			if errWaitMore != nil {
				_ = innerErr.AddConsequence(errWaitMore)
			}
		}
		return innerErr
	})
	if xerr != nil {
		return xerr
	}

	// Remove metadata
	return rn.core.Delete(task)
}

// GetDefaultRouteIP returns the IP of the LAN default route
func (rn network) GetDefaultRouteIP(task concurrency.Task) (ip string, xerr fail.Error) {
	if rn.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return "", fail.InvalidParameterError("task", "cannot be nil")
	}

	ip = ""
	xerr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if an.VIP != nil && an.VIP.PrivateIP != "" {
			ip = an.VIP.PrivateIP
		} else {
			objpgw, innerErr := LoadHost(task, rn.GetService(), an.GatewayID)
			if innerErr != nil {
				return innerErr
			}
			ip = objpgw.(*host).getPrivateIP(task)
			return nil
		}
		return nil
	})
	return ip, xerr
}

// getDefaultRouteIP ...
func (rn network) getDefaultRouteIP(task concurrency.Task) string {
	if rn.IsNull() {
		return ""
	}
	ip, _ := rn.GetDefaultRouteIP(task)
	return ip
}

// GetEndpointIP returns the IP of the internet IP to reach the network
func (rn network) GetEndpointIP(task concurrency.Task) (ip string, xerr fail.Error) {
	ip = ""
	if rn.IsNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return ip, fail.InvalidParameterError("task", "cannot be nil")
	}

	xerr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if an.VIP != nil && an.VIP.PublicIP != "" {
			ip = an.VIP.PublicIP
		} else {
			objpgw, inErr := LoadHost(task, rn.GetService(), an.GatewayID)
			if inErr != nil {
				return inErr
			}
			ip = objpgw.(*host).getPublicIP(task)
			return nil
		}
		return nil
	})
	return ip, xerr
}

// getEndpointIP ...
func (rn network) getEndpointIP(task concurrency.Task) string {
	if rn.IsNull() {
		return ""
	}
	ip, _ := rn.GetEndpointIP(task)
	return ip
}

// HasVirtualIP tells if the network uses a VIP a default route
func (rn network) HasVirtualIP(task concurrency.Task) bool {
	if rn.IsNull() {
		logrus.Errorf(fail.InvalidInstanceError().Error())
		return false
	}

	var found bool
	xerr := rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		found = an.VIP != nil
		return nil
	})
	return xerr == nil && found
}

// GetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (rn network) GetVirtualIP(task concurrency.Task) (vip *abstract.VirtualIP, xerr fail.Error) {
	if rn.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	xerr = rn.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		vip = an.VIP
		return nil
	})
	if xerr != nil {
		return nil, fail.Wrap(xerr, "cannot get network virtual IP")

	}
	if vip == nil {
		return nil, fail.NotFoundError("failed to find Virtual IP binded to gateways for network '%s'", rn.GetName())
	}
	return vip, nil
}

// GetCIDR returns the CIDR of the network
func (rn network) GetCIDR(task concurrency.Task) (cidr string, xerr fail.Error) {
	if rn.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return "", fail.InvalidParameterError("task", "cannot be nil")
	}

	cidr = ""
	xerr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		cidr = an.CIDR
		return nil
	})
	return cidr, xerr
}

// CIDR returns the CIDR of the network
// Intended to be used when objn is notoriously not nil (because previously checked)
func (rn network) CIDR(task concurrency.Task) string {
	cidr, _ := rn.GetCIDR(task)
	return cidr
}

// ToProtocol converts resources.Network to protocol.Network
func (rn network) ToProtocol(task concurrency.Task) (_ *protocol.Network, xerr fail.Error) {
	if rn.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, true, "").Entering()
	defer tracer.Exiting()

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to convert resources.Network to *protocol.Network")
		}
	}()

	var (
		secondaryGatewayID string
		gw                 resources.Host
		vip                *abstract.VirtualIP
	)

	// Get primary gateway GetID
	gw, xerr = rn.GetGateway(task, true)
	if xerr != nil {
		return nil, xerr
	}
	primaryGatewayID := gw.GetID()

	// Get secondary gateway id if such a gateway exists
	gw, xerr = rn.GetGateway(task, false)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return nil, xerr
		}
	} else {
		secondaryGatewayID = gw.GetID()
	}

	pn := &protocol.Network{
		Id:                 rn.GetID(),
		Name:               rn.GetName(),
		Cidr:               rn.CIDR(task),
		GatewayId:          primaryGatewayID,
		SecondaryGatewayId: secondaryGatewayID,
		Failover:           rn.HasVirtualIP(task),
		// GetState:              rn.GetState(),
	}

	vip, xerr = rn.GetVirtualIP(task)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return nil, xerr
		}
	}
	if vip != nil {
		pn.VirtualIp = converters.VirtualIPFromAbstractToProtocol(*vip)
	}

	return pn, nil
}

// BindSecurityGroup binds a security group to the host; if enabled is true, apply it immediately
func (rn *network) BindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup, enabled bool) fail.Error {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.NetworkSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// First check if the security group is not already registered for the host with the exact same state
			for k, v := range nsgV1.ByID {
				if k == sgID && v.Disabled == !enabled {
					return fail.DuplicateError("security group '%s' already binded to host")
				}
			}

			// Not found, add it
			nsgV1.ByID[sgID].Disabled = !enabled
			nsgV1.ByName[sg.GetName()].Disabled = !enabled

			// If enabled, apply it
			return sg.BindToNetwork(task, rn, enabled)
		})
	})
}

// UnbindSecurityGroup unbinds a security group from the host
func (rn *network) UnbindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) fail.Error {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.NetworkSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// Check if the security group is listed for the host, inot already registered for the host with the exact same state
			found := false
			for k := range nsgV1.ByID {
				if k == sgID {
					found = true
					break
				}
			}
			// If not found, consider request successful
			if !found {
				return nil
			}

			// found, delete it from properties
			delete(nsgV1.ByID, sgID)
			delete(nsgV1.ByName, sg.GetName())

			// unbind security group from host on remote service side
			return sg.UnbindFromNetwork(task, rn)
		})
	})
}

// ListSecurityGroups returns a slice of security groups binded to host
func (rn *network) ListSecurityGroups(task concurrency.Task, kind string) (list []*propertiesv1.SecurityGroupBond, _ fail.Error) {
	var nullList []*propertiesv1.SecurityGroupBond
	if rn.IsNull() {
		return nullList, fail.InvalidInstanceError()
	}
	if task == nil {
		return nullList, fail.InvalidParameterError("task", "cannot be nil")
	}

	if kind == "" {
		kind = "all"
	}
	loweredKind := strings.ToLower(kind)
	switch loweredKind {
	case "all", "enabled", "disabled":
		// continue
	default:
		return nil, fail.InvalidParameterError("kind", fmt.Sprintf("invalid value '%s'", kind))
	}

	return list, rn.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.NetworkSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = filterBondsByKind(nsgV1.ByID, loweredKind)
			return nil
		})
	})
}

// EnableSecurityGroup enables a binded security group to network
func (rn *network) EnableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) fail.Error {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.NetworkSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// First check if the security group is not already registered for the host with the exact same state
			var found bool
			for k := range nsgV1.ByID {
				if k == sgID {
					found = true
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not binded to network '%s'", sg.GetName(), rn.GetID())
			}

			// found, update properties
			nsgV1.ByID[sgID].Disabled = false
			nsgV1.ByName[sg.GetName()].Disabled = false

			// Bind the security group on provider side; if already bound (*fail.ErrDuplicate), consider as a success
			innerXErr := sg.GetService().BindSecurityGroupToNetwork(rn.GetID(), sgID)
			switch innerXErr.(type) {
			case *fail.ErrDuplicate:
				return nil
			default:
				return innerXErr
			}
		})
	})
}

// DisableSecurityGroup disables an already binded security group on network
func (rn *network) DisableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) fail.Error {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.NetworkSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// First check if the security group is not already registered for the host with the exact same state
			var found bool
			for k := range nsgV1.ByID {
				if k == sgID {
					found = true
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not binded to network '%s'", sg.GetName(), rn.GetID())
			}

			// found, update properties
			nsgV1.ByID[sgID].Disabled = true
			nsgV1.ByName[sg.GetName()].Disabled = true

			// Bind the security group on provider side; if security group not bound (*fail.ErrNotFound), consider as a success
			innerXErr := sg.GetService().UnbindSecurityGroupFromNetwork(rn.GetID(), sgID)
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				return nil
			default:
				return innerXErr
			}
		})
	})
}
