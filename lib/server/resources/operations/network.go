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
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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
func NewNetwork(svc iaas.Service) (resources.Network, error) {
	if svc == nil {
		return nullNetwork(), scerr.InvalidParameterError("svc", "cannot be nil")
	}

	core, err := NewCore(svc, "network", networksFolderName, &abstract.Network{})
	if err != nil {
		return nullNetwork(), err
	}

	return &network{core: core}, nil
}

// LoadNetwork loads the metadata of a network
func LoadNetwork(task concurrency.Task, svc iaas.Service, ref string) (resources.Network, error) {
	if task == nil {
		return nullNetwork(), scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nullNetwork(), scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nullNetwork(), scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	objn, err := NewNetwork(svc)
	if err != nil {
		return nullNetwork(), err
	}
	err = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return objn.Read(task, ref)
		},
		10*time.Second, // FIXME: parameterize
	)
	if err != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := err.(retry.ErrTimeout); ok {
			logrus.Debugf("timeout reading metadata of network '%s'", ref)
			err = scerr.NotFoundError("network '%s' not found: %s", ref, err.Error())
		}
		return nullNetwork(), err
	}
	return objn, nil
}

// IsNull tells if the instance corresponds to network Null Value
func (objn *network) IsNull() bool {
	return objn == nil || objn.core.IsNull()
}

// Create creates a network
func (objn *network) Create(task concurrency.Task, req abstract.NetworkRequest, gwname string, gwSizing *abstract.HostSizingRequirements) (err error) {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(
		task,
		true,
		"('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.Image, req.HA,
	).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	// defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)
	defer scerr.OnPanic(&err)

	// Check if network already exists and is managed by SafeScale
	svc := objn.SafeGetService()
	_, err = LoadNetwork(task, svc, req.Name)
	if err == nil {
		return scerr.DuplicateError("network '%s' already exists", req.Name)
	}

	// Verify if the network already exist and in this case is not managed by SafeScale
	_, err = svc.GetNetworkByName(req.Name)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound:
		case scerr.ErrInvalidRequest, scerr.ErrTimeout:
			return err
		default:
			return err
		}
	} else {
		return scerr.DuplicateError("network '%s' already exists (not managed by SafeScale)", req.Name)
	}

	// Verify the CIDR is not routable
	if req.CIDR != "" {
		routable, err := utils.IsCIDRRoutable(req.CIDR)
		if err != nil {
			return scerr.Wrap(err, "failed to determine if CIDR is not routable")
		}
		if routable {
			return scerr.InvalidRequestError("cannot create such a network, CIDR must not be routable; please choose an appropriate CIDR (RFC1918)")
		}
	}

	// Create the network
	logrus.Debugf("Creating network '%s' ...", req.Name)
	an, err := svc.CreateNetwork(req)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound, scerr.ErrInvalidRequest, scerr.ErrTimeout:
			return err
		default:
			return err
		}
	}

	// Starting from here, delete network if exiting with error
	defer func() {
		if err != nil && an != nil && !req.KeepOnFailure {
			derr := svc.DeleteNetwork(an.ID)
			if derr != nil {
				switch derr.(type) {
				case scerr.ErrNotFound:
					logrus.Errorf("failed to delete network, resource not found: %+v", derr)
				case scerr.ErrTimeout:
					logrus.Errorf("failed to delete network, timeout: %+v", derr)
				default:
					logrus.Errorf("failed to delete network, other reason: %+v", derr)
				}
				err = scerr.AddConsequence(err, derr)
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
		an.VIP, err = svc.CreateVIP(an.ID, fmt.Sprintf("for gateways of network %s", an.Name))
		if err != nil {
			switch err.(type) {
			case scerr.ErrNotFound, scerr.ErrTimeout:
				return err
			default:
				return err
			}
		}

		// Starting from here, delete VIP if exists with error
		defer func() {
			if err != nil && !req.KeepOnFailure {
				if an != nil {
					derr := svc.DeleteVIP(an.VIP)
					if derr != nil {
						logrus.Errorf("failed to delete VIP: %+v", derr)
						err = scerr.AddConsequence(err, derr)
					}
				}
			}
		}()
	}

	// Write network object metadata
	// logrus.Debugf("Saving network metadata '%s' ...", network.Name)
	err = objn.Carry(task, an)
	if err != nil {
		return err
	}

	// Starting from here, delete network metadata if exits with error
	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := objn.core.Delete(task)
			if derr != nil {
				logrus.Errorf("failed to delete network metadata: %+v", derr)
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	err = objn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		an.NetworkState = networkstate.GATEWAY_CREATION
		return nil
	})
	if err != nil {
		return err
	}

	var template *abstract.HostTemplate
	tpls, err := svc.SelectTemplatesBySize(*gwSizing, false)
	if err != nil {
		return scerr.Wrap(err, "failed to find appropriate template")
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
		return scerr.NotFoundError("error creating network: no host template matching requirements for gateway")
	}
	if req.Image == "" {
		// if gwSizing.Image != "" {
		req.Image = gwSizing.Image
		// }
	}
	if req.Image == "" {
		cfg, err := svc.GetConfigurationOptions()
		if err != nil {
			return err
		}
		req.Image = cfg.GetString("DefaultImage")
		gwSizing.Image = req.Image
	}
	img, err := svc.SearchImage(req.Image)
	if err != nil {
		return scerr.Wrap(err, "unable to create network gateway")
	}

	networkName := objn.SafeGetName()
	var primaryGatewayName, secondaryGatewayName string
	if failover || gwname == "" {
		primaryGatewayName = "gw-" + networkName
	} else {
		primaryGatewayName = gwname
	}
	if failover {
		secondaryGatewayName = "gw2-" + networkName
	}

	keypairName := "kp_" + networkName
	keypair, err := svc.CreateKeyPair(keypairName)
	if err != nil {
		return err
	}

	gwRequest := abstract.HostRequest{
		ImageID:       img.ID,
		Networks:      []*abstract.Network{an},
		KeyPair:       keypair,
		TemplateID:    template.ID,
		KeepOnFailure: req.KeepOnFailure,
	}

	var (
		primaryGateway, secondaryGateway   resources.Host
		primaryUserdata, secondaryUserdata *userdata.Content
		primaryTask, secondaryTask         concurrency.Task
		secondaryErr                       error
		secondaryResult                    concurrency.TaskResult
	)

	// Starts primary gateway creation
	primaryRequest := gwRequest
	primaryRequest.ResourceName = primaryGatewayName
	primaryRequest.HostName = primaryGatewayName
	if req.Domain != "" {
		primaryRequest.HostName += "." + req.Domain
	}
	primaryTask, err = task.StartInSubtask(objn.taskCreateGateway, data.Map{
		"request": primaryRequest,
		"sizing":  *gwSizing,
		"primary": true,
	})
	if err != nil {
		return err
	}

	// Starts secondary gateway creation if asked for
	if failover {
		secondaryRequest := gwRequest
		secondaryRequest.ResourceName = secondaryGatewayName
		secondaryRequest.HostName = secondaryGatewayName
		if req.Domain != "" {
			secondaryRequest.HostName += "." + req.Domain
		}
		secondaryTask, err = task.StartInSubtask(objn.taskCreateGateway, data.Map{
			"request": secondaryRequest,
			"sizing":  *gwSizing,
			"primary": false,
		})
		if err != nil {
			return err
		}
	}

	primaryResult, primaryErr := primaryTask.Wait()
	if primaryErr == nil {
		result, ok := primaryResult.(data.Map)
		if !ok {
			return scerr.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(primaryResult).String())
		}
		primaryGateway = result["host"].(resources.Host)
		primaryUserdata = result["userdata"].(*userdata.Content)

		// Starting from here, deletes the primary gateway if exiting with error
		defer func() {
			if err != nil && !req.KeepOnFailure {
				logrus.Debugf("Cleaning up on failure, deleting gateway '%s'...", primaryGateway.SafeGetName())
				derr := objn.deleteGateway(task, primaryGateway)
				if derr != nil {
					switch derr.(type) {
					case scerr.ErrTimeout:
						logrus.Warnf("We should wait") // FIXME Wait until gateway no longer exists
					default:
					}
					err = scerr.AddConsequence(err, derr)
				} else {
					logrus.Infof("Cleaning up on failure, gateway '%s' deleted", primaryGateway.SafeGetName())
				}
				if failover {
					failErr := objn.unbindHostFromVIP(task, an.VIP, primaryGateway)
					err = scerr.AddConsequence(err, failErr)
				}
			}
		}()
	}
	if failover && secondaryTask != nil {
		secondaryResult, secondaryErr = secondaryTask.Wait()
		if secondaryErr == nil {
			result, ok := secondaryResult.(data.Map)
			if !ok {
				return scerr.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(secondaryResult).String())
			}

			secondaryGateway = result["host"].(resources.Host)
			secondaryUserdata = result["userdata"].(*userdata.Content)

			// Starting from here, deletes the secondary gateway if exiting with error
			defer func() {
				if err != nil && !req.KeepOnFailure {
					derr := objn.deleteGateway(task, secondaryGateway)
					if derr != nil {
						switch derr.(type) {
						case scerr.ErrTimeout:
							logrus.Warnf("We should wait") // FIXME Wait until gateway no longer exists
						default:
						}
						err = scerr.AddConsequence(err, derr)
					}
					failErr := objn.unbindHostFromVIP(task, an.VIP, secondaryGateway)
					err = scerr.AddConsequence(err, failErr)
				}
			}()
		}
	}
	if primaryErr != nil {
		return scerr.Wrap(primaryErr, "failed to create gateway '%s'", primaryGatewayName)
	}
	if secondaryErr != nil {
		return scerr.Wrap(secondaryErr, "failed to create gateway '%s'", secondaryGatewayName)
	}

	// Update metadata of network object
	err = objn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// an.GatewayID = primaryGateway.SafeGetID()
		primaryUserdata.PrimaryGatewayPrivateIP = primaryGateway.SafeGetID()
		primaryUserdata.PrimaryGatewayPublicIP = primaryGateway.SafeGetPublicIP(task)
		primaryUserdata.IsPrimaryGateway = true
		if an.VIP != nil {
			primaryUserdata.DefaultRouteIP = an.VIP.PrivateIP
			primaryUserdata.EndpointIP = an.VIP.PublicIP
		} else {
			primaryUserdata.DefaultRouteIP = primaryUserdata.PrimaryGatewayPrivateIP
			primaryUserdata.EndpointIP = primaryUserdata.PrimaryGatewayPublicIP
		}
		if secondaryGateway != nil {
			// an.SecondaryGatewayID = secondaryGateway.SafeGetID()
			primaryUserdata.SecondaryGatewayPrivateIP = secondaryGateway.SafeGetID()
			secondaryUserdata.PrimaryGatewayPrivateIP = primaryUserdata.PrimaryGatewayPrivateIP
			secondaryUserdata.SecondaryGatewayPrivateIP = primaryUserdata.SecondaryGatewayPrivateIP
			primaryUserdata.SecondaryGatewayPublicIP = secondaryGateway.SafeGetPublicIP(task)
			secondaryUserdata.PrimaryGatewayPublicIP = primaryUserdata.PrimaryGatewayPublicIP
			secondaryUserdata.SecondaryGatewayPublicIP = primaryUserdata.SecondaryGatewayPublicIP
			secondaryUserdata.IsPrimaryGateway = false
		}

		return nil
	})
	if err != nil {
		return err
	}

	// As hosts are gateways, the configuration stopped on phase 'netsec', the remaining phases 'hwga', 'sysfix' and 'final' have to be run
	primaryTask, err = concurrency.NewTask()
	if err != nil {
		return err
	}
	err = objn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		an.NetworkState = networkstate.GATEWAY_CONFIGURATION
		return nil
	})
	if err != nil {
		return err
	}

	primaryTask, err = primaryTask.Start(objn.taskFinalizeGatewayConfiguration, data.Map{
		"host":     primaryGateway,
		"userdata": primaryUserdata,
	})
	if err != nil {
		return err
	}
	if failover && secondaryTask != nil {
		secondaryTask, err = concurrency.NewTask()
		if err != nil {
			return err
		}
		secondaryTask, err = secondaryTask.Start(objn.taskFinalizeGatewayConfiguration, data.Map{
			"host":     secondaryGateway,
			"userdata": secondaryUserdata,
		})
		if err != nil {
			return err
		}
	}
	_, primaryErr = primaryTask.Wait()
	if primaryErr != nil {
		return primaryErr
	}
	if failover && secondaryTask != nil {
		_, secondaryErr = secondaryTask.Wait()
		if secondaryErr != nil {
			return secondaryErr
		}
	}

	// Updates network state in metadata
	// logrus.Debugf("Updating network metadata '%s' ...", network.Name)
	return objn.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		an.NetworkState = networkstate.READY
		return nil
	})
}

// deleteGateway eases a gateway deletion
// Note: doesn't use gw.Delete() because by rule a Delete on a gateway is not permitted
func (objn *network) deleteGateway(task concurrency.Task, gw resources.Host) (err error) {
	name := gw.SafeGetName()
	err = objn.SafeGetService().DeleteHost(gw.SafeGetID())
	if err == nil {
		err = gw.(*host).core.Delete(task)
	}
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound:
			logrus.Errorf("Failed to delete gateway '%s', resource not found: %v", name, err)
		case scerr.ErrTimeout:
			logrus.Errorf("Failed to delete gateway '%s', timeout: %v", name, err)
		default:
			logrus.Errorf("Failed to delete gateway '%s': %v", name, err)
		}
	}
	return err
}

func (objn *network) unbindHostFromVIP(task concurrency.Task, vip *abstract.VirtualIP, host resources.Host) error {
	name := host.SafeGetName()
	err := objn.SafeGetService().UnbindHostFromVIP(vip, host.SafeGetID())
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound, scerr.ErrTimeout:
			logrus.Debugf("Cleaning up on failure, failed to remove '%s' gateway bind from VIP: %v", name, err)
		default:
			logrus.Debugf("Cleaning up on failure, failed to remove '%s' gateway bind from VIP: %v", name, err)
		}
		return err
	}
	logrus.Infof("Cleaning up on failure, host '%s' bind removed from VIP", name)
	return nil
}

// Browse walks through all the metadata objects in network
func (objn *network) Browse(task concurrency.Task, callback func(*abstract.Network) error) error {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "can't be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "can't be nil")
	}

	return objn.core.BrowseFolder(task, func(buf []byte) error {
		an := abstract.NewNetwork()
		err := an.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(an)
	})
}

// AttachHost links host ID to the network
func (objn *network) AttachHost(task concurrency.Task, host resources.Host) (err error) {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if host == nil {
		return scerr.InvalidParameterError("host", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, true, "("+host.SafeGetName()+")").Entering()
	defer tracer.OnExitTrace()
	// defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)
	defer scerr.OnPanic(&err)

	hostID := host.SafeGetID()
	hostName := host.SafeGetName()

	return objn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(task, networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			networkHostsV1.ByID[hostID] = hostName
			networkHostsV1.ByName[hostName] = hostID
			return nil
		})
	})
}

// DetachHost unlinks host ID from network
func (objn *network) DetachHost(task concurrency.Task, hostID string) (err error) {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, true, "('"+hostID+"')").Entering()
	defer tracer.OnExitTrace()
	// defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)
	defer scerr.OnPanic(&err)

	return objn.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(task, networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
func (objn *network) ListHosts(task concurrency.Task) (_ []resources.Host, err error) {
	if objn.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, true, "").Entering()
	defer tracer.OnExitTrace()
	// defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)
	defer scerr.OnPanic(&err)

	var list []resources.Host
	err = objn.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(task, networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			svc := objn.SafeGetService()
			for id := range networkHostsV1.ByID {
				host, err := LoadHost(task, svc, id)
				if err != nil {
					return err
				}
				list = append(list, host)
			}
			return nil
		})
	})
	if err != nil {
		logrus.Errorf("Error listing hosts: %+v", err)
	}
	return list, nil
}

// GetGateway returns the gateway related to network
func (objn *network) GetGateway(task concurrency.Task, primary bool) (_ resources.Host, err error) {
	if objn.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer scerr.OnPanic(&err)

	tracer := concurrency.NewTracer(nil, true, "").Entering()
	defer tracer.OnExitTrace()
	// defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)
	defer scerr.OnPanic(&err)

	var gatewayID string
	err = objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if primary {
			gatewayID = an.GatewayID
		} else {
			gatewayID = an.SecondaryGatewayID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if gatewayID == "" {
		return nil, scerr.NotFoundError("no gateway ID found in network properties")
	}
	return LoadHost(task, objn.SafeGetService(), gatewayID)
}

// SafeGetGateway returns a resources.Host corresponding to the gateway requested. May return HostNull if no gateway exists.
func (objn *network) SafeGetGateway(task concurrency.Task, primary bool) resources.Host {
	host, _ := objn.GetGateway(task, primary)
	return host
}

// Delete deletes network referenced by ref
func (objn *network) Delete(task concurrency.Task) (err error) {
	if objn.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	// defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)
	defer scerr.OnPanic(&err)

	objn.SafeLock(task)
	defer objn.SafeUnlock(task)

	// var gwID string
	err = objn.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		svc := objn.SafeGetService()

		// Check if hosts are still attached to network according to metadata
		var errorMsg string
		innerErr := props.Inspect(task, networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
				return scerr.NotAvailableError(errorMsg)
			}
			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		// Leave a chance to abort
		taskStatus, _ := task.GetStatus()
		if taskStatus == concurrency.ABORTED {
			return scerr.AbortedError(nil)
		}

		// 1st delete primary gateway
		if an.GatewayID != "" {
			stop := false
			rh, innerErr := LoadHost(task, svc, an.GatewayID)
			if innerErr != nil {
				if _, ok := innerErr.(scerr.ErrNotFound); !ok {
					return innerErr
				}
				stop = true
			}
			if !stop {
				if rh != nil {
					logrus.Debugf("Deleting gateway '%s'...", rh.SafeGetName())
					innerErr = objn.deleteGateway(task, rh)
					if innerErr != nil { // allow no gateway, but log it
						if _, ok := err.(scerr.ErrNotFound); ok {
							logrus.Errorf("Failed to delete primary gateway: %s", innerErr.Error())
						} else {
							return innerErr
						}
					}
				}
			} else {
				logrus.Infof("Primary Gateway of network '%s' appears to be already deleted", an.Name)
			}
		}

		// 2nd delete secondary gateway
		if an.SecondaryGatewayID != "" {
			stop := false
			rh, innerErr := LoadHost(task, svc, an.SecondaryGatewayID)
			if innerErr != nil {
				if _, ok := innerErr.(scerr.ErrNotFound); !ok {
					return innerErr
				}
				stop = true
			}
			if !stop {
				if rh != nil {
					logrus.Debugf("Deleting gateway '%s'...", rh.SafeGetName())
					innerErr = objn.deleteGateway(task, rh)
					if innerErr != nil { // allow no gateway, but log it
						if _, ok := innerErr.(scerr.ErrNotFound); ok { // nolint
							logrus.Errorf("failed to delete secondary gateway: %s", innerErr.Error())
						} else {
							return innerErr
						}
					}
				}
			} else {
				logrus.Infof("Secondary Gateway of network '%s' appears to be already deleted", an.Name)
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
			case scerr.ErrNotFound:
				// If network doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
				logrus.Warnf("network not found on provider side, cleaning up metadata.")
				return err
			case scerr.ErrTimeout:
				logrus.Error("cannot delete network due to a timeout")
				waitMore = true
			default:
				logrus.Error("cannot delete network, other reason")
			}
		}
		if waitMore {
			errWaitMore := retry.WhileUnsuccessfulDelay1Second(
				func() error {
					recNet, recErr := svc.GetNetwork(an.ID)
					if recNet != nil {
						return fmt.Errorf("still there")
					}
					if _, ok := recErr.(scerr.ErrNotFound); ok {
						return nil
					}
					return scerr.Wrap(recErr, "another kind of error")
				},
				temporal.GetContextTimeout(),
			)
			if errWaitMore != nil {
				innerErr = scerr.AddConsequence(err, errWaitMore)
			}
		}
		return innerErr
	})
	if err != nil {
		return err
	}

	// Delete metadata
	return objn.core.Delete(task)
}

// GetDefaultRouteIP returns the IP of the LAN default route
func (objn *network) GetDefaultRouteIP(task concurrency.Task) (ip string, err error) {
	if objn.IsNull() {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	ip = ""
	err = objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if an.VIP != nil && an.VIP.PrivateIP != "" {
			ip = an.VIP.PrivateIP
		} else {
			objpgw, innerErr := LoadHost(task, objn.SafeGetService(), an.GatewayID)
			if innerErr != nil {
				return innerErr
			}
			ip = objpgw.SafeGetPrivateIP(task)
			return nil
		}
		return nil
	})
	return ip, err
}

// SafeGetDefaultRouteIP ...
func (objn *network) SafeGetDefaultRouteIP(task concurrency.Task) string {
	if objn.IsNull() {
		return ""
	}
	ip, _ := objn.GetDefaultRouteIP(task)
	return ip
}

// GetEndpointIP returns the IP of the internet IP to reach the network
func (objn *network) GetEndpointIP(task concurrency.Task) (ip string, err error) {
	if objn.IsNull() {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	ip = ""
	err = objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if an.VIP != nil && an.VIP.PublicIP != "" {
			ip = an.VIP.PublicIP
		} else {
			objpgw, inErr := LoadHost(task, objn.SafeGetService(), an.GatewayID)
			if inErr != nil {
				return inErr
			}
			ip = objpgw.SafeGetPublicIP(task)
			return nil
		}
		return nil
	})
	return ip, err
}

// SafeGetEndpointIP ...
func (objn *network) SafeGetEndpointIP(task concurrency.Task) string {
	if objn.IsNull() {
		return ""
	}
	ip, _ := objn.GetEndpointIP(task)
	return ip
}

// HasVirtualIP tells if the network uses a VIP a default route
func (objn *network) HasVirtualIP(task concurrency.Task) bool {
	if objn.IsNull() {
		logrus.Errorf(scerr.InvalidInstanceError().Error())
		return false
	}

	var found bool
	err := objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		found = an.VIP != nil
		return nil
	})
	return err == nil && found
}

// GetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (objn *network) GetVirtualIP(task concurrency.Task) (vip *abstract.VirtualIP, err error) {
	if objn == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	err = objn.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		vip = an.VIP
		return nil
	})
	if err != nil {
		return nil, scerr.Wrap(err, "cannot get network virtual IP")

	}
	if vip == nil {
		return nil, scerr.NotFoundError("failed to find Virtual IP binded to gateways for network '%s'", objn.SafeGetName())
	}
	return vip, nil
}

// GetCIDR returns the CIDR of the network
func (objn *network) GetCIDR(task concurrency.Task) (cidr string, err error) {
	if objn == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	cidr = ""
	err = objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		cidr = an.CIDR
		return nil
	})
	return cidr, err
}

// SafeGetCIDR returns the CIDR of the network
// Intended to be used when objn is notoriously not nil (because previously checked)
func (objn *network) SafeGetCIDR(task concurrency.Task) string {
	cidr, _ := objn.GetCIDR(task)
	return cidr
}

// ToProtocol converts resources.Network to protocol.Network
func (objn *network) ToProtocol(task concurrency.Task) (_ *protocol.Network, err error) {
	if objn == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, true, "").Entering()
	defer tracer.OnExitTrace()

	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "failed to convert resources.Network to *protocol.Network")
		}
	}()

	var (
		secondaryGatewayID string
		gw                 resources.Host
		vip                *abstract.VirtualIP
	)

	// Get primary gateway ID
	gw, err = objn.GetGateway(task, true)
	if err != nil {
		return nil, err
	}
	primaryGatewayID := gw.SafeGetID()

	// Get secondary gateway id if such a gateway exists
	gw, err = objn.GetGateway(task, false)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return nil, err
		}
	} else {
		secondaryGatewayID = gw.SafeGetID()
	}

	pn := &protocol.Network{
		Id:                 objn.SafeGetID(),
		Name:               objn.SafeGetName(),
		Cidr:               objn.SafeGetCIDR(task),
		GatewayId:          primaryGatewayID,
		SecondaryGatewayId: secondaryGatewayID,
		Failover:           objn.HasVirtualIP(task),
		// State:              objn.SafeGetState(),
	}

	vip, err = objn.GetVirtualIP(task)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return nil, err
		}
	}
	if vip != nil {
		pn.VirtualIp = converters.VirtualIPFromAbstractToProtocol(*vip)
	}

	return pn, nil
}
