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

package hosts

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// hostsFolderName is the technical name of the container used to store networks info
	hostsFolderName = "hosts"
)

// Host ...
type Host struct {
	*operations.Core
	properties     *serialize.JSONProperties
	installMethods map[uint8]installmethod.Enum
	sshProfile     *system.SSHConfig
}

// New ...
func New(svc iaas.Service) (*Host, error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}

	core, err := operations.NewCore(svc, "host", hostsFolderName)
	if err != nil {
		return nil, err
	}

	return &Host{Core: core}, nil
}

// Load ...
func Load(task concurrency.Task, svc iaas.Service, ref string) (*Host, error) {
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	objh, err := New(svc)
	if err != nil {
		return nil, err
	}

	var inErr error
	err = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			inErr = objh.Read(task, ref)
			if inErr != nil {
				if _, ok := inErr.(scerr.ErrNotFound); ok {
					return inErr
				}
			}
			return nil
		},
		10*time.Second,
	)

	// If retry timed out, log it and return error ErrNotFound
	if err != nil {
		if _, ok := err.(retry.ErrTimeout); ok {
			logrus.Debugf("timeout reading metadata of host '%s'", ref)
			return nil, scerr.NotFoundError("failed to load metadata of host '%s'", ref)
		}
		return nil, err
	}
	// Returns the error different than ErrNotFound to caller
	if inErr != nil {
		return nil, inErr
	}
	return objh, nil
}

// // Properties returns the extensions of the host
// func (objh *Host) Properties(task concurrency.Task) (_ *serialize.JSONProperties, err error) {
// 	if objh == nil {
// 		return nil, scerr.InvalidInstanceError()
// 	}
// 	if task == nil {
// 		return nil, scerr.InvalidParameterError("task", "cannot be nil")
// 	}

// 	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
// 	defer tracer.OnExitTrace()()
// 	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

// 	objh.Core.RLock(task)
// 	defer objh.Core.RUnlock(task)

// 	if objh.properties == nil {
// 		return nil, scerr.InvalidInstanceContentError("objh.properties", "cannot be nil")
// 	}
// 	return objh.properties, nil
// }

// Browse walks through host folder and executes a callback for each entries
func (objh *Host) Browse(task concurrency.Task, callback func(*abstracts.HostCore) error) (err error) {
	if objh == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	return objh.Core.BrowseFolder(task, func(buf []byte) error {
		host := abstracts.NewHostCore()
		err = host.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(host)
	})
}

func (objh *Host) State(task concurrency.Task) (hoststate.Enum, error) {
	if objh == nil {
		return hoststate.UNKNOWN, scerr.InvalidInstanceError()
	}
	state := hoststate.UNKNOWN
	err := objh.Reload(task)
	if err != nil {
		return state, err
	}
	err = objh.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		core, ok := clonable.(*abstracts.HostCore)
		if !ok {
			return scerr.InconsistentError("'*abstracts.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		state = core.LastState
		return nil
	})
	return state, err
}

// Create creates a new host and its metadata
// If the metadata is already carrying a host, returns scerr.ErrNotAvailable
func (objh *Host) Create(task concurrency.Task, hostReq abstracts.HostRequest, hostDef abstracts.HostSizingRequirements) error {
	if objh == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	hostname := objh.Name()
	if hostname != "" {
		return scerr.NotAvailableError(fmt.Sprintf("already carrying host '%s'", hostname))
	}

	svc := objh.Service()
	_, err := svc.GetHostByName(hostReq.ResourceName)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return scerr.Wrap(err, fmt.Sprintf("failure creating host: failed to check if host resource name '%s' is already used", hostReq.ResourceName))
		}
	} else {
		return scerr.DuplicateError(fmt.Sprintf("failed to create host '%s': name is already used", hostReq.ResourceName))
	}

	var (
		// networkID, networkName string
		objn resources.Network
		// objpgw, objsgw *Host
	)

	if len(hostReq.Networks) > 0 {
		// By convention, default network is the first of the list
		rn := hostReq.Networks[0]
		objn, err = networkfactory.Load(task, svc, rn.ID)
		if err != nil {
			return err
		}
	} else {
		objn, _, err = getOrCreateDefaultNetwork(task, svc)
		if err != nil {
			return err
		}
		err = objn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
			rn, ok := clonable.(*abstracts.Network)
			if !ok {
				return scerr.InconsistentError("'*abstracts.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostReq.Networks = append(hostReq.Networks, rn)
			return nil
		})
		if err != nil {
			return err
		}
	}
	// networkName := objn.Name()

	// if hostReq.DefaultGatewayID == "" {
	// 	hostReq.DefaultGatewayID = objpgw.ID(task)
	// }

	templates, err := svc.SelectTemplatesBySize(hostDef, false)
	if err != nil {
		return scerr.Wrap(err, "failed to find template corresponding to requested resources")
	}
	var template abstracts.HostTemplate
	if len(templates) > 0 {
		template = *(templates[0])
		msg := fmt.Sprintf("Selected host template: '%s' (%d core%s", template.Name, template.Cores, utils.Plural(uint(template.Cores)))
		if template.CPUFreq > 0 {
			msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
		}
		msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
		if template.GPUNumber > 0 {
			msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, utils.Plural(uint(template.GPUNumber)))
			if template.GPUType != "" {
				msg += fmt.Sprintf(" %s", template.GPUType)
			}
		}
		msg += ")"
		logrus.Infof(msg)
	} else {
		logrus.Errorf("failed to find template corresponding to requested resources")
		return scerr.Wrap(err, "failed to find template corresponding to requested resources")
	}

	var img *abstracts.Image
	err = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			var inErr error
			img, inErr = svc.SearchImage(hostReq.ImageID)
			return inErr
		},
		10*time.Second,
	)
	if err != nil {
		return scerr.Wrap(err, "failed to find image to use on compute resource")
	}

	hostReq.ImageID = img.ID
	hostReq.TemplateID = template.ID

	hf, userDataContent, err := svc.CreateHost(hostReq)
	if err != nil {
		if _, ok := err.(scerr.ErrInvalidRequest); ok {
			return err
		}
		return scerr.Wrap(err, fmt.Sprintf("failed to create compute resource '%s'", hostReq.ResourceName))
	}

	defer func() {
		if err != nil {
			derr := svc.DeleteHost(hf.Core.ID)
			if derr != nil {
				logrus.Errorf("after failure, failed to cleanup by deleting host '%s': %v", hf.Core.Name, derr)
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Creates metadata early to "reserve" host name
	err = objh.Carry(task, hf.Core)
	if err != nil {
		return err
	}

	// Updates properties in metadata
	err = objh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		innerErr := props.Alter(hostproperty.SizingV2, func(clonable data.Clonable) error {
			hostSizingV2, ok := clonable.(*propertiesv2.HostSizing)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv2.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			hostSizingV2.AllocatedSize = converters.HostEffectiveSizingAbstractsToProperty(hf.Sizing)
			hostSizingV2.RequestedSize = converters.HostSizingRequirementsAbstractsToProperty(hostDef)
			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		// Starting from here, delete host metadata if exiting with error
		defer func() {
			if innerErr != nil {
				derr := objh.Core.Delete(task)
				if derr != nil {
					logrus.Errorf("After failure, failed to cleanup by removing host metadata")
				}
			}
		}()

		// Sets host extension DescriptionV1
		innerErr = props.Alter(hostproperty.DescriptionV1, func(clonable data.Clonable) error {
			hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			_ = hostDescriptionV1.Replace(converters.HostDescriptionFromAbstractsToProperty(hf.Description))
			creator := ""
			hostname, _ := os.Hostname()
			if curUser, err := user.Current(); err == nil {
				creator := curUser.Username
				if hostname != "" {
					creator += "@" + hostname
				}
				if curUser.Name != "" {
					creator += " (" + curUser.Name + ")"
				}
			} else {
				creator = "unknown@" + hostname
			}
			hostDescriptionV1.Creator = creator
			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		// Updates host property propertiesv1.HostNetwork
		// var (
		// 	defaultNetworkID string
		// 	gatewayID string
		// )
		return props.Alter(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_ = hostNetworkV1.Replace(converters.HostNetworkFromAbstractsToProperty(hf.Network))
			hostNetworkV1.DefaultNetworkID = objn.ID()
			if objn.Name() != abstracts.SingleHostNetworkName {
				hostNetworkV1.IsGateway = (hostReq.DefaultRouteIP == "")
			} else {
				hostNetworkV1.IsGateway = false
			}

			return nil
		})
	})
	if err != nil {
		return err
	}

	logrus.Infof("Compute resource created: '%s'", objh.Name())

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	logrus.Infof("Waiting start of SSH service on remote host '%s' ...", objh.Name())

	// TODO configurable timeout here
	status, err := objh.waitInstallPhase(task, "phase1")
	if err != nil {
		if _, ok := err.(*scerr.ErrTimeout); ok {
			return scerr.Wrap(err, "Timeout creating a host")
		}
		if abstracts.IsProvisioningError(err) {
			logrus.Errorf("%+v", err)
			return scerr.Wrap(err, "error creating the host [%s], error provisioning the new host, please check safescaled logs", objh.Name())
		}
		return err
	}

	// -- update host property propertiesv1.System --
	err = objh.Alter(task, func(clonable data.Clonable, properties *serialize.JSONProperties) error {
		return properties.Alter(hostproperty.SystemV1, func(clonable data.Clonable) error {
			systemV1, ok := clonable.(*propertiesv1.HostSystem)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostSystem' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			parts := strings.Split(status, ",")
			systemV1.Type = parts[1]
			systemV1.Flavor = parts[2]
			systemV1.Image = hostReq.ImageID
			return nil
		})
	})
	if err != nil {
		return err
	}

	// -- Updates host link with networks --
	for _, rn := range hostReq.Networks {
		err := objh.updateNetwork(task, rn.ID)
		if err != nil {
			return err
		}
	}

	// Executes userdata phase2 script to finalize host installation
	filepath := "/opt/safescale/var/tmp/user_data.phase2.sh"
	userDataPhase2, err := userDataContent.Generate("phase2")
	if err != nil {
		return err
	}
	err = objh.PushStringToFile(task, string(userDataPhase2), filepath, "", "", "")
	if err != nil {
		return err
	}
	command := fmt.Sprintf("sudo bash %s; exit $?", filepath)
	// Executes the script on the remote host
	retcode, _, stderr, err := objh.Run(task, command, 0, 0)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return scerr.NewError(fmt.Sprintf("failed to finalize host '%s' installation: %s", objh.Name(), stderr), nil, nil)
	}

	// Reboot host
	command = "sudo systemctl reboot"
	retcode, _, stderr, err = objh.Run(task, command, 0, 0)
	if err != nil {
		return err
	}

	// FIXME: configurable timeout here
	_, err = objh.waitInstallPhase(task, "ready")
	if err != nil {
		if _, ok := err.(*scerr.ErrTimeout); ok {
			return scerr.Wrap(err, "timeout creating a host")
		}
		if abstracts.IsProvisioningError(err) {
			logrus.Errorf("%+v", err)
			return scerr.NewError(fmt.Sprintf("error creating the host [%s], error provisioning the new host, please check safescaled logs", objh.Name()), nil, nil)
		}

		return err
	}
	logrus.Infof("SSH service started on host '%s'.", objh.Name())

	return nil
}

func (objh *Host) waitInstallPhase(task concurrency.Task, phase string) (string, error) {
	sshDefaultTimeout := int(temporal.GetHostTimeout().Minutes())
	if sshDefaultTimeoutCandidate := os.Getenv("SSH_TIMEOUT"); sshDefaultTimeoutCandidate != "" {
		num, err := strconv.Atoi(sshDefaultTimeoutCandidate)
		if err == nil {
			logrus.Debugf("Using custom timeout of %d minutes", num)
			sshDefaultTimeout = num
		}
	}
	sshCfg, err := objh.SSHConfig(task)
	if err != nil {
		return "", err
	}

	// TODO: configurable timeout here
	status, err := sshCfg.WaitServerReady(task, phase, time.Duration(sshDefaultTimeout)*time.Minute)
	if err != nil {
		if _, ok := err.(*scerr.ErrTimeout); ok {
			return status, scerr.Wrap(err, "Timeout creating a host")
		}
		if abstracts.IsProvisioningError(err) {
			logrus.Errorf("%+v", err)
			return status, scerr.Wrap(err, "error creating the host [%s], error provisioning the new host, please check safescaled logs", objh.Name())
		}
		return status, err
	}
	return status, nil
}

func (objh *Host) updateNetwork(task concurrency.Task, networkID string) error {
	objn, err := networkfactory.Load(task, objh.Core.Service(), networkID)
	if err != nil {
		return err
	}
	return objn.Alter(task, func(clonable data.Clonable, properties *serialize.JSONProperties) error {
		return properties.Alter(networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			networkHostsV1.ByName[objh.Name()] = objh.ID()
			networkHostsV1.ByID[objh.ID()] = objh.Name()
			return nil
		})
	})
}

// WaitSSHReady waits until SSH responds successfully
func (objh *Host) WaitSSHReady(task concurrency.Task, timeout time.Duration) (status string, err error) {
	if objh == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	sshCfg, err := objh.SSHConfig(task)
	if err != nil {
		return "", err
	}
	return sshCfg.WaitServerReady(task, "ready", timeout)
}

// getOrCreateDefaultNetwork gets network abstracts.SingleHostNetworkName or create it if necessary
// We don't want metadata on this network, so we use directly provider api instead of services
func getOrCreateDefaultNetwork(task concurrency.Task, svc iaas.Service) (resources.Network, resources.Host, error) {
	if objn, err := networkfactory.Load(task, svc, abstracts.SingleHostNetworkName); err == nil {
		objpgw, err := objn.Gateway(task, true)
		if err != nil {
			return nil, nil, err
		}
		return objn, objpgw, nil
	}

	objn, err := networkfactory.New(svc)
	if err != nil {
		return nil, nil, err
	}

	request := abstracts.NetworkRequest{
		Name:      abstracts.SingleHostNetworkName,
		IPVersion: IPVersion.IPv4,
		CIDR:      "10.0.0.0/8",
	}
	err = objn.Create(task, request, "", nil)
	if err != nil {
		return nil, nil, err
	}

	defer func() {
		if err != nil {
			derr := objn.Delete(task)
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	objpgw, err := objn.Gateway(task, true)
	if err != nil {
		return nil, nil, err
	}
	return objn, objpgw, nil
}

// Delete deletes a host with its metadata and updates network links
func (objh *Host) Delete(task concurrency.Task) error {
	if objh == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	objh.Lock(task)
	defer objh.Unlock(task)

	svc := objh.Service()

	hostID := objh.ID()
	err := objh.Alter(task, func(_ data.Clonable, properties *serialize.JSONProperties) error {
		// Don't remove a host having shares that are currently remotely mounted
		var shares map[string]*propertiesv1.HostShare
		inErr := properties.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) error {
			sharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			shares := sharesV1.ByID
			shareCount := len(shares)
			for _, hostShare := range shares {
				count := len(hostShare.ClientsByID)
				if count > 0 {
					// clients found, checks if these clients already exists...
					for _, hostID := range hostShare.ClientsByID {
						_, inErr := LoadHost(task, svc, hostID)
						if inErr == nil {
							return scerr.NotAvailableError(fmt.Sprintf("exports %d share%s and at least one share is mounted", shareCount, utils.Plural(uint(shareCount))))
						}
					}
				}
			}
			return nil
		})
		if inErr != nil {
			return inErr
		}

		// Don't remove a host with volumes attached
		inErr = properties.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			nAttached := len(hostVolumesV1.VolumesByID)
			if nAttached > 0 {
				return scerr.NotAvailableError(fmt.Sprintf("host has %d volume%s attached", nAttached, utils.Plural(uint(nAttached))))
			}
			return nil
		})
		if inErr != nil {
			return inErr
		}

		// Don't remove a host that is a gateway
		inErr = properties.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			if hostNetworkV1.IsGateway {
				return scerr.NotAvailableError(fmt.Sprintf("cannot delete host, it's a gateway that can only be deleted through its network"))
			}
			return nil
		})
		if inErr != nil {
			return inErr
		}

		// If host mounted shares, unmounts them before anything else
		var mounts []*propertiesv1.HostShare
		inErr = properties.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			for _, i := range hostMountsV1.RemoteMountsByPath {
				// Retrieve share data
				objs, loopErr := NewShare(svc)
				if loopErr != nil {
					return loopErr
				}
				loopErr = objs.Read(task, i.ShareID)
				if loopErr != nil {
					return loopErr
				}

				// Retrieve data about the server serving the share
				objserver, loopErr := objs.Server(task)
				if loopErr != nil {
					return loopErr
				}
				// Retrieve data about share from its server
				share, loopErr := objserver.Share(task, i.ShareID)
				if loopErr != nil {
					return loopErr
				}
				mounts = append(mounts, share)
			}
			return nil
		})
		if inErr != nil {
			return inErr
		}

		// Unmounts tier shares mounted on host (done outside the previous host.Properties.Reading() section, because
		// Unmount() have to lock for write, and won't succeed while host.Properties.Reading() is running,
		// leading to a deadlock)
		for _, item := range mounts {
			objs, loopErr := LoadShare(task, svc, item.ID)
			if loopErr != nil {
				return loopErr
			}
			loopErr = objs.Unmount(task, hostID)
			if loopErr != nil {
				return loopErr
			}
		}

		// if host exports shares, delete them
		for _, share := range shares {
			objs, loopErr := NewShare(svc)
			if loopErr == nil {
				loopErr = objs.Read(task, share.Name)
			}
			if loopErr != nil {
				return loopErr
			}
			loopErr = objs.Delete(task)
			if loopErr != nil {
				return loopErr
			}
		}

		// Update networks property prosv1.NetworkHosts to remove the reference to the host
		inErr = properties.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String()))
			}
			hostID := objh.ID()
			hostName := objh.Name()
			errors := []error{}
			for k := range hostNetworkV1.NetworksByID {
				objn, loopErr := LoadNetwork(task, svc, k)
				if loopErr != nil {
					logrus.Errorf(loopErr.Error())
					errors = append(errors, loopErr)
					continue
				}
				loopErr = objn.Alter(task, func(clonable data.Clonable, netprops *serialize.JSONProperties) error {
					// rn, ok := clonable.(*abstracts.Network)
					// if !ok {
					// 	return scerr.InconsistentError(fmt.Sprintf("'*abstracts.Network' expected, '%s' provided", reflect.TypeOf(clonable).String()))
					// }
					return netprops.Alter(networkproperty.HostsV1, func(clonable data.Clonable) error {
						networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
						if !ok {
							return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String()))
						}
						delete(networkHostsV1.ByID, hostID)
						delete(networkHostsV1.ByName, hostName)
						return nil
					})
				})
				if loopErr != nil {
					logrus.Errorf(loopErr.Error())
					errors = append(errors, loopErr)
				}
			}
			return scerr.ErrListError(errors)
		})
		if inErr != nil {
			return inErr
		}

		// Conditions are met, delete host
		waitForDeletion := true
		delErr := retry.WhileUnsuccessfulDelay1Second(
			func() error {
				// FIXME: need to remove retry from svc.DeleteHost!
				err := svc.DeleteHost(hostID)
				if err != nil {
					if _, ok := err.(scerr.ErrNotFound); !ok {
						return scerr.Wrap(err, "cannot delete host")
					}
					logrus.Warn("host resource not found on provider side, host metadata will be removed for consistency")
					waitForDeletion = false
				}
				return nil
			},
			time.Minute*5,
		)
		if delErr != nil {
			return delErr
		}

		// wait for effective host deletion
		if waitForDeletion {
			inErr = retry.WhileUnsuccessfulDelay5SecondsTimeout(
				func() error {
					// FIXME: need to remove retry from svc.GetHostState!
					if state, stateErr := svc.GetHostState(objh.ID()); stateErr == nil {
						logrus.Warnf("While deleting the status was [%s]", state)
						if state == HostState.ERROR {
							return fmt.Errorf("host is in state ERROR")
						}
					} else {
						return stateErr
					}
					return nil
				},
				time.Minute*2, // FIXME: static duration
			)
			if inErr != nil {
				return inErr
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Deletes metadata from Object Storage
	err = objh.Core.Delete(task)
	if err != nil {
		if _, ok := err.(*scerr.ErrNotFound); ok {
			// If entry not found, consider a success
			return nil
		}
		return err
	}

	//FIXME: do we really need to rebuild deleted host ? We lost all config, data, ... hosted so what is the point ?
	// select { // FIXME Unorthodox usage of context
	// case <-ctx.Done():
	// 	logrus.Warnf("Host delete cancelled by safescale")
	// 	var hostBis *abstracts.Host
	// 	err2 := host.Properties.Inspect(hostproperty.SizingV1, func(v interface{}) error {
	// 		hostSizingV1 := v.(*propertiesv1.HostSizing)
	// 		return host.Properties.Inspect(hostproperty.NetworkV1, func(v interface{}) error {
	// 			hostNetworkV1 := v.(*propertiesv1.HostNetwork)
	// 			//FIXME: host's os name is not stored in metadatas so we used ubuntu 18.04 by default
	// 			var err3 error
	// 			sizing := abstracts.SizingRequirements{
	// 				MinCores:    hostSizingV1.AllocatedSize.Cores,
	// 				MaxCores:    hostSizingV1.AllocatedSize.Cores,
	// 				MinFreq:     hostSizingV1.AllocatedSize.CPUFreq,
	// 				MinGPU:      hostSizingV1.AllocatedSize.GPUNumber,
	// 				MinRAMSize:  hostSizingV1.AllocatedSize.RAMSize,
	// 				MaxRAMSize:  hostSizingV1.AllocatedSize.RAMSize,
	// 				MinDiskSize: hostSizingV1.AllocatedSize.DiskSize,
	// 			}
	// 			hostBis, err3 = handler.Create(context.Background(), host.Name, hostNetworkV1.DefaultNetworkID, "ubuntu 18.04", (len(hostNetworkV1.PublicIPv4)+len(hostNetworkV1.PublicIPv6)) != 0, &sizing, true)
	// 			if err3 != nil {
	// 				return fmt.Errorf("failed to stop host deletion : %s", err3.Error())
	// 			}
	// 			return nil
	// 		})
	// 	})
	// 	if err2 != nil {
	// 		return fmt.Errorf("failed to cancel host deletion : %s", err2.Error())
	// 	}

	// 	buf, err2 := hostBis.Serialize()
	// 	if err2 != nil {
	// 		return fmt.Errorf("deleted Host recreated by safescale")
	// 	}
	// 	return fmt.Errorf("deleted Host recreated by safescale : %s", buf)

	// default:
	// }

	return nil
}

// SSHConfig loads SSH configuration for host from metadata
//
// FIXME: system.SSHConfig should be able to carry data about secondary Gateway
//        Currently, if primary gateway is down, ssh to a host in the network will fail
func (objh *Host) SSHConfig(task concurrency.Task) (_ *system.SSHConfig, err error) {
	if objh == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	err = objh.Inspect(task, func(clonable data.Clonable, properties *serialize.JSONProperties) error {
		if objh.sshProfile == nil {
			rh, ok := clonable.(*abstracts.Host)
			if !ok {
				return scerr.InconsistentError("'*abstracts.Host' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			var sshProfile *system.SSHConfig
			ip, inErr := objh.AccessIP(task)
			if inErr != nil {
				return inErr
			}
			sshProfile = &system.SSHConfig{
				PrivateKey: rh.PrivateKey,
				Port:       22,
				Host:       ip,
				User:       abstracts.DefaultUser,
			}

			inErr = properties.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
				hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				if hostNetworkV1.DefaultNetworkID != "" {
					svc := objh.Service()
					objn, err := LoadNetwork(task, svc, hostNetworkV1.DefaultNetworkID)
					if err != nil {
						return err
					}
					objpgw, err := objn.Gateway(task, true)
					if err != nil {
						return err
					}
					gwErr := objpgw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
						rgw, ok := clonable.(*abstracts.Host)
						if !ok {
							return scerr.InconsistentError(fmt.Sprintf("'*abstracts.Host' expected, '%s' provided", reflect.TypeOf(clonable).String()))
						}
						ip, ipErr := objpgw.AccessIP(task)
						if ipErr != nil {
							return ipErr
						}
						gatewayConfig := system.SSHConfig{
							PrivateKey: rgw.PrivateKey,
							Port:       22,
							Host:       ip,
							User:       abstracts.DefaultUser,
						}
						sshProfile.GatewayConfig = &gatewayConfig
						return nil
					})
					if gwErr != nil {
						return gwErr
					}
					objsgw, err := objn.Gateway(task, false)
					if err != nil {
						return err
					}
					gwErr = objsgw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
						rgw, ok := clonable.(*abstracts.Host)
						if !ok {
							return scerr.InconsistentError(fmt.Sprintf("'*abstracts.Host' expected, '%s' provided", reflect.TypeOf(clonable).String()))
						}
						ip, ipErr := objpgw.AccessIP(task)
						if ipErr != nil {
							return ipErr
						}
						gatewayConfig := system.SSHConfig{
							PrivateKey: rgw.PrivateKey,
							Port:       22,
							Host:       ip,
							User:       abstracts.DefaultUser,
						}
						sshProfile.SecondaryGatewayConfig = &gatewayConfig
						return nil
					})
					if gwErr != nil {
						return gwErr
					}
				}
				return nil
			})
			if inErr != nil {
				return inErr
			}
			objh.sshProfile = sshProfile
		}
	})
	if err != nil {
		return nil, err
	}
	return objh.sshProfile, err
}

// Run tries to execute command 'cmd' on the host
func (objh *Host) Run(task concurrency.Task, cmd string, connectionTimeout, executionTimeout time.Duration) (int, string, string, error) {
	if objh == nil {
		return 0, "", "", scerr.InvalidInstanceError()
	}
	if task != nil {
		return 0, "", "", scerr.InvalidParameterError("task", "cannot be nil")
	}
	if cmd == "" {
		return 0, "", "", scerr.InvalidParameterError("cmd", "cannot be empty string")
	}

	var (
		stdOut, stdErr string
		retCode        int
		err            error
	)

	// retrieve ssh config to perform some commands
	ssh, err := objh.SSHConfig(task)
	if err != nil {
		return 0, "", "", err
	}

	if executionTimeout < temporal.GetHostTimeout() {
		executionTimeout = temporal.GetHostTimeout()
	}
	if connectionTimeout < temporal.DefaultConnectionTimeout {
		connectionTimeout = temporal.DefaultConnectionTimeout
	}
	if connectionTimeout > executionTimeout {
		connectionTimeout = executionTimeout + temporal.GetContextTimeout()
	}

	taskCtx, err := task.Context()
	if err != nil {
		return -1, "", "", err
	}
	runctx, cancel := context.WithTimeout(taskCtx, executionTimeout)
	defer cancel()

	hostName := objh.Name()
	err = retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			retCode, stdOut, stdErr, err = run(runctx, ssh, cmd, executionTimeout)
			return err
		},
		connectionTimeout,
		func(t retry.Try, v Verdict.Enum) {
			if v == Verdict.Retry {
				logrus.Printf("Remote SSH service on host '%s' isn't ready, retrying...", hostName)
			}
		},
	)
	return retCode, stdOut, stdErr, err
}

// run executes command on the host
func run(ctx context.Context, ssh *system.SSHConfig, cmd string, timeout time.Duration) (int, string, string, error) {
	// Create the command
	sshCmd, err := ssh.Command(cmd)
	if err != nil {
		return 0, "", "", err
	}

	retcode, stdout, stderr, err := sshCmd.RunWithTimeout(ctx, nil, timeout)
	if err != nil {
		retcode = -1
		return -1, "", "", err
	}
	// If retcode == 255, ssh connection failed
	if retcode == 255 {
		return -1, "", "", fmt.Errorf("failed to connect")
	}
	return retcode, stdout, stderr, err
}

// Pull downloads a file from host
func (objh *Host) Pull(task concurrency.Task, target, source string, timeout time.Duration) (int, string, string, error) {
	if objh == nil {
		return 0, "", "", scerr.InvalidInstanceError()
	}
	if source == "" {
		return 0, "", "", scerr.InvalidParameterError("source", "cannot be empty string")
	}
	if target == "" {
		return 0, "", "", scerr.InvalidParameterError("target", "cannot be empty string")
	}

	// retrieve ssh config to perform some commands
	ssh, err := objh.SSHConfig(task)
	if err != nil {
		return 0, "", "", err
	}

	if timeout < temporal.GetHostTimeout() {
		timeout = temporal.GetHostTimeout()
	}

	taskCtx, err := task.Context()
	if err != nil {
		return -1, "", "", err
	}
	runctx, cancel := context.WithTimeout(taskCtx, timeout)
	defer cancel()

	return ssh.Copy(runctx, target, source, false)
}

// Push uploads a file to host
func (objh *Host) Push(task concurrency.Task, source, target, owner, mode string, timeout time.Duration) (int, string, string, error) {
	if objh == nil {
		return 0, "", "", scerr.InvalidInstanceError()
	}
	if source == "" {
		return 0, "", "", scerr.InvalidParameterError("source", "cannot be empty string")
	}
	if target == "" {
		return 0, "", "", scerr.InvalidParameterError("target", "cannot be empty string")
	}

	// retrieve ssh config to perform some commands
	ssh, err := objh.SSHConfig(task)
	if err != nil {
		return 0, "", "", err
	}

	if timeout < temporal.GetHostTimeout() {
		timeout = temporal.GetHostTimeout()
	}
	taskCtx, err := task.Context()
	if err != nil {
		return -1, "", "", err
	}
	runCtx, cancelCtx := context.WithTimeout(taskCtx, timeout)
	defer cancelCtx()

	retcode, stdout, stderr, err := ssh.Copy(runCtx, target, source, true)
	if err != nil {
		return retcode, stdout, stderr, err
	}
	cmd := ""
	if owner != "" {
		cmd += "chown " + owner + ` '` + target + `' ;`
	}
	if mode != "" {
		cmd += "chmod " + mode + ` '` + target + `'`
	}
	if cmd != "" {
		retcode, stdout, stderr, err = ssh.Run(runCtx, cmd)
	}
	return retcode, stdout, stderr, err
}

// Share returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
func (objh *Host) Share(task concurrency.Task, shareRef string) (*propertiesv1.HostShare, error) {
	if objh == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if shareRef == "" {
		return nil, scerr.InvalidParameterError("shareRef", "cannot be empty string")
	}

	var (
		hostShare *propertiesv1.HostShare
		// ok        bool
	)
	err := objh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		// rh, ok := clonable.(*abstracts.Host)
		// if !ok {
		// 	return scerr.InconsistentError("'*abstracts.Host' expected, '%s' provided", reflect.TypeOf(clonable).String())
		// }
		// props, inErr := objh.Properties(task)
		// if inErr != nil {
		// 	return inErr
		// }
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) error {
			sharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if hostShare, ok = sharesV1.ByID[shareRef].Clone().(*propertiesv1.HostShare); ok {
				return nil
			}
			if _, ok := sharesV1.ByName[shareRef]; ok {
				hostShare = sharesV1.ByID[sharesV1.ByName[shareRef]].Clone().(*propertiesv1.HostShare)
				return nil
			}
			return scerr.NotFoundError("share '%s' not found in server '%s' metadata", shareRef, objh.Name())
		})
	})
	if err != nil {
		return nil, err
	}
	return hostShare, nil
}

// Start starts the host
func (objh *Host) Start(task concurrency.Task) (err error) {
	if objh == nil {
		return scerr.InvalidInstanceError()
	}
	if task != nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	scerr.OnPanic(&err)()

	hostName := objh.Name()
	hostID := objh.ID()

	svc := objh.Service()
	err = svc.StartHost(hostID)
	if err != nil {
		return err
	}

	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			return svc.WaitHostState(hostID, HostState.STARTED, temporal.GetHostTimeout())
		},
		5*time.Minute,
	)
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("timeout waiting host '%s' to be started", hostName))
	}
	return nil
}

// Stop stops the host
func (objh *Host) Stop(task concurrency.Task) (err error) {
	if objh == nil {
		return scerr.InvalidInstanceError()
	}
	if task != nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	hostName := objh.Name()
	hostID := objh.ID()

	svc := objh.Service()
	err = svc.StopHost(hostID)
	if err != nil {
		return err
	}

	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			return svc.WaitHostState(hostID, HostState.STOPPED, temporal.GetHostTimeout())
		},
		// FIXME: static value
		5*time.Minute,
	)
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("timeout waiting host '%s' to be started", hostName))
	}
	return nil
}

// Reboot reboots the host
func (objh *Host) Reboot(task concurrency.Task) error {
	err := objh.Stop(task)
	if err != nil {
		return err
	}
	return objh.Start(task)
}

// Resize ...
// not yet implemented
func (objh *Host) Resize(hostSize abstracts.SizingRequirements) error {
	return scerr.NotImplementedError("Host.Resize() not yet implemented")
}

// AddFeature handles 'safescale host add-feature <host name or id> <feature name>'
func (objh *Host) AddFeature(task concurrency.Task, name string, vars data.Map, settings resources.InstallSettings) (resources.InstallResults, error) {
	if objh == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(Trace.Host, task, fmt.Sprintf("(%s)", featureName)).GoingIn()
	defer tracer.OnExitTrace()

	feature, err := features.New(task, nameÒ)
	if err != nil {
		return nil, err
	}
	return objh.Alter(task, func(_ data.Clonable, props *serialize.jsonProperties) error {
		results, err := feature.Add(task, host, values, settings)
		if err != nil {
			return err
		}

		// updates HostFeatures property for host
		return props.Alter(property.HostFeatures, func(clonable data.Clonable) error {
			hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return scerr.InconsistentError("expected '*propertiesv1.HostFeatures', received '%s'", reflect.TypeOf(clonable))
			}
			hostsFeaturesV1.Installed[name] = &propertiesv1.HostFeature{
				Context:  "host",
				Requires: features.Requires(),
			}
			return nil
		})
	})
}

// CheckFeature ...
func (objh *Host) CheckFeature(task concurrency.Task, name string, vars data.Map, settings resources.InstallSettings) (resources.InstallResults, error) {
	if objh == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("featureName", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(Trace.Host, task, fmt.Sprintf("(%s)", featureName)).In()
	defer tracer.Out()

	feature, err := features.New(task, objh.Service(), name)
	if err != nil {
		return nil, err
	}

	// Wait for SSH service on remote host first
	// ssh, err := mh.GetSSHConfig(task)
	// if err != nil {
	// 	return srvutils.ThrowErr(err)
	// }
	// _, err = ssh.WaitServerReady(2 * time.Minute)
	// if err != nil {
	// 	return srvutils.ThrowErr(err)
	// }

	return feature.Check(objh, vars, settings)
}

// DeleteFeature handles 'safescale host delete-feature <host name> <feature name>'
func (objh *Host) DeleteFeature(
	task concurrency.Task,
	name string, vars data.Map, settings resources.InstallSettings,
) (resources.InstallResults, error) {
	if objh == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return scerr.InvalidParameterError("featureName", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(Trace.Host, task, fmt.Sprintf("(%s)", name)).GoingIn()
	defer tracer.OnExitTrace()

	feature, err := features.New(task, objh.Service(), name)
	if err != nil {
		return err
	}

	// // Wait for SSH service on remote host first
	// ssh, err := mh.GetSSHConfig(task)
	// if err != nil {
	// 	return srvutils.ThrowErr(err)
	// }
	// _, err = ssh.WaitServerReady(2 * time.Minute)
	// if err != nil {
	// 	return srvutils.ThrowErr(err)
	// }

	return objh.Alter(task, func(_ data.Clonable, props *serialize.jsonProperties) error {
		results, err := feature.Remove(objh, vars, settings)
		if err != nil {
			return srvutils.InfraErrf(err, "error uninstalling feature '%s' on '%s'", featureName, hostName)
		}
		if !results.Successful() {
			msg := fmt.Sprintf("failed to delete feature '%s' from host '%s'", featureName, hostName)
			tracer.Trace(utils.Capitalize(msg) + ":\n" + results.AllErrorMessages())
			return srvutils.LogicErr(fmt.Errorf(msg))
		}

		// updates HostFeatures property for host
		return props.Alter(property.HostFeatures, func(clonable data.Clonable) error {
			hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return scerr.InconsistentError("expected '*propertiesv1.HostFeatures', received '%s'", reflect.TypeOf(clonable))
			}
			delete(hostsFeaturesV1, name)
			return nil
		})
	})
}

// Type returns the type of the target
//
// satisfies install.Targetable interface
func (objh *Host) TargetType() string {
	return "host"
}

// PublicIP returns the public IP address of the host
func (objh *Host) PublicIP(task concurrency.Task) (ip string, err error) {
	ip = ""
	if objh == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	objh.RLock(task)
	defer objh.RUnlock(task)

	props, err := objh.Properties(task)
	if err != nil {
		return "", err
	}
	err = props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
		hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
		if !ok {
			return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		ip = hostNetworkV1.PublicIPv4
		if ip == "" {
			ip = hostNetworkV1.PublicIPv6
		}
		return nil
	})
	return ip, err
}

// PrivateIP ...
func (objh *Host) PrivateIP(task concurrency.Task) (ip string, err error) {
	ip = ""
	if objh == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	props, err := objh.Properties(task)
	if err != nil {
		return "", err
	}
	err = props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
		hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
		if !ok {
			return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if len(hostNetworkV1.IPv4Addresses) > 0 {
			ip = hostNetworkV1.IPv4Addresses[hostNetworkV1.DefaultNetworkID]
			if ip == "" {
				ip = hostNetworkV1.IPv6Addresses[hostNetworkV1.DefaultNetworkID]
			}
		}
		return nil
	})
	return ip, err
}

// AccessIP returns the IP to reach the host
func (objh *Host) AccessIP(task concurrency.Task) (string, error) {
	if objh == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	ip, err := objh.PublicIP(task)
	if err == nil && ip == "" {
		ip, err = objh.PrivateIP(task)
	}
	return ip, nil
}

// InstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
//
// satisfies interface install.Targetable
func (objh *Host) InstallMethods(task concurrency.Task) map[uint8]installmethod.Enum {
	if objh == nil {
		logrus.Error(scerr.InvalidInstanceError().Error())
		return nil
	}
	if task == nil {
		logrus.Error(scerr.InvalidParameterError("task", "cannot be nil").Error())
		return nil
	}

	objh.Lock(task)
	defer objh.Unlock(task)

	if objh.installMethods == nil {
		objh.installMethods = map[uint8]installmethod.Enum{}

		_ = objh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
			// props, inErr := objh.Properties(task)
			// if inErr != nil {
			// 	return inErr
			// }

			// Ignore error in this special case; will fallback to use bash method if cannot determine operating system type and flavor
			var index uint8
			_ = props.Inspect(hostproperty.SystemV1, func(clonable data.Clonable) error {
				systemV1, ok := clonable.(*propertiesv1.HostSystem)
				if !ok {
					logrus.Error(scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostSystem' expected, '%s' provided", reflect.TypeOf(clonable).String())))
				}
				if systemV1.Type == "linux" {
					switch systemV1.Flavor {
					case "centos":
						fallthrough
					case "redhat":
						index++
						objh.installMethods[index] = installmethod.Yum
					case "debian":
						fallthrough
					case "ubuntu":
						index++
						objh.installMethods[index] = installmethod.Apt
					case "fedora":
						index++
						objh.installMethods[index] = installmethod.Dnf
					}
				}
				return nil
			})
			index++
			objh.installMethods[index] = installmethod.Bash
			return nil
		})
	}
	return objh.installMethods
}

// InstalledFeatures returns a list of installed features
//
// satisfies interface install.Targetable
func (objh *Host) InstalledFeatures(task concurrency.Task) []string {
	var list []string
	return list
}

// ComplementFeatureParameters configures parameters that are appropriate for the target
//
// satisfies interface install.Targetable
func (objh *Host) ComplementFeatureParameters(task concurrency.Task, v data.Map) error {
	if objh == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if v == nil {
		return scerr.InvalidParameterError("v", "cannot be nil")
	}

	v["Hostname"] = objh.Name()

	ip, err := objh.PrivateIP(task)
	if err != nil {
		return err
	}
	v["HostIP"] = ip

	ip, err = objh.PublicIP(task)
	if err != nil {
		return err
	}
	v["PublicIP"] = ip

	if _, ok := v["Username"]; !ok {
		v["Username"] = abstracts.DefaultUser
	}

	// FIXME: gateway stuff has to be refactored (2 gateways possible)
	return objh.Inspect(task, func(clonable data.Clonable) error {
		props, inErr := objh.Properties(task)
		if inErr != nil {
			return inErr
		}
		return props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			networkID := hostNetworkV1.DefaultGatewayID
			if networkID == "" {
				return scerr.NotFoundError("failed to find network defined for host")
			}
			objn, inErr := LoadNetwork(task, objh.Service(), networkID)
			if inErr != nil {
				return inErr
			}

			objpgw, inErr := objn.Gateway(task, true)
			if inErr != nil {
				return inErr
			}
			ip, inErr := objpgw.PrivateIP(task)
			if inErr != nil {
				return inErr
			}
			v["GatewayIP"] = ip

			ip, inErr = objpgw.PublicIP(task)
			if inErr != nil {
				return inErr
			}
			v["PublicIP"] = ip

			objsgw, inErr := objn.Gateway(task, false)
			if inErr != nil {
				if _, ok := inErr.(*scerr.ErrNotFound); !ok {
					return inErr
				}
			} else {
				ip, inErr = objsgw.PrivateIP(task)
				if inErr != nil {
					return inErr
				}
				v["SecondaryGatewayIP"] = ip
				ip, inErr = objsgw.PublicIP(task)
				if inErr != nil {
					return inErr
				}
				v["SecondaryPublicIP"] = ip
			}
			ip, inErr = objn.EndpointIP(task)
			if inErr != nil {
				return inErr
			}
			v["EndpointIP"] = ip

			ip, inErr = objn.DefaultRouteIP(task)
			if inErr != nil {
				return inErr
			}
			v["DefaultRouteIP"] = ip
			return nil
		})
	})
}

// IsClusterMember returns true if the host is member of a cluster
func (objh *Host) IsClusterMember(task concurrency.Task) (yes bool, err error) {
	yes = false
	if objh == nil {
		return false, scerr.InvalidInstanceError()
	}
	if task == nil {
		return false, scerr.InvalidParameterError("task", "cannot be nil")
	}

	props, err := objh.Properties(task)
	if err != nil {
		return false, err
	}
	err = props.Inspect(hostproperty.ClusterMembershipV1, func(clonable data.Clonable) error {
		hostClusterMembershipV1, ok := clonable.(*propertiesv1.HostClusterMembership)
		if !ok {
			return scerr.InconsistentError(fmt.Sprintf("'*propertiesv1.HostClusterMembership' expected, '%s' provided", reflect.TypeOf(clonable).String()))
		}
		yes = (hostClusterMembershipV1.Cluster != "")
		return nil
	})
	return yes, err
}

// PushStringToFile creates a file 'filename' on remote 'host' with the content 'content'
func (objh *Host) PushStringToFile(task concurrency.Task, content string, filename string, owner, group, rights string) (err error) {
	if objh == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if content == "" {
		return scerr.InvalidParameterError("content", "cannot be empty string")
	}
	if filename == "" {
		return scerr.InvalidParameterError("filename", "cannot be empty string")
	}

	hostName := objh.Name()
	f, err := system.CreateTempFileFromString(content, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %s", err.Error())
	}
	to := fmt.Sprintf("%s:%s", hostName, filename)
	deleted := false
	retryErr := retry.WhileUnsuccessful(
		func() error {
			var (
				retcode int
				inErr   error
			)
			retcode, _, _, inErr = objh.Push(task, f.Name(), filename, temporal.GetExecutionTimeout())
			if inErr != nil {
				return inErr
			}
			if retcode != 0 {
				// If retcode == 1 (general copy error), retry. It may be a temporary network incident
				if retcode == 1 && !deleted {
					// File may exist on target, try to remove it
					_, _, _, inErr = objh.Run(task, fmt.Sprintf("sudo rm -f %s", filename), temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
					if inErr == nil {
						deleted = true
					}
					return fmt.Errorf("file may exist on remote with inappropriate access rights, deleted it and retrying")
				}
				if system.IsSCPRetryable(retcode) {
					err = fmt.Errorf("failed to copy temporary file to '%s' (retcode: %d=%s)", to, retcode, system.SCPErrorString(retcode))
				}
				return nil
			}
			return nil
		},
		1*time.Second,
		2*time.Minute,
	)
	_ = os.Remove(f.Name())
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return fmt.Errorf("timeout trying to copy temporary file to '%s': %s", to, retryErr.Error())
		}
		return err
	}

	cmd := ""
	if owner != "" {
		cmd += "sudo chown " + owner + " " + filename
	}
	if group != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "sudo chgrp " + group + " " + filename
	}
	if rights != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "sudo chmod " + rights + " " + filename
	}
	retryErr = retry.WhileUnsuccessful(
		func() error {
			var retcode int
			retcode, _, _, err = objh.Run(task, cmd, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
			if err != nil {
				return err
			}
			if retcode != 0 {
				err = fmt.Errorf("failed to change rights of file '%s' (retcode=%d)", to, retcode)
				return nil
			}
			return nil
		},
		2*time.Second,
		1*time.Minute,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return scerr.Wrapf(err, "timeout trying to change rights of file '%s' on host '%s'", filename, hostName)
		default:
			return scerr.Wrapf(retryErr, "failed to change rights of file '%s' on host '%s'", filename, hostName)
		}
	}
	return nil
}

// DefaultNetwork returns the Network instance corresponding to host default network
func (objh *Host) DefaultNetwork(task concurrency.Task) (objn resources.Network, err error) {
	if objh == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	err = objh.Inspect(task, func(_ data.Clonable) error {
		props, inErr := objh.Properties(task)
		if inErr != nil {
			return inErr
		}
		return props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			networkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*rscpropertiesv1.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if networkV1.DefaultNetworkID != "" {
				var inErr error
				objn, inErr = LoadNetwork(task, objh.Service(), networkV1.DefaultNetworkID)
				return inErr
			}
			return scerr.NotFoundError("no default network associated with host")
		})
	})
	if err != nil {
		return nil, err
	}
	return objn, nil
}

// ToProtocolHost convert an resources.Host to protocol format
func (objh *Host) ToProtocolHost(task concurrency.Task, in resources.Host) (pbHost *protocol.Host, err error) {
	if objh == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}

	defer scerr.OnPanic(&err)()

	var (
		host                *abstracts.Host
		hostNetworkV1       *propertiesv1.HostNetwork
		hostSizingV1        *propertiesv1.HostSizing
		hostVolumesV1       *propertiesv1.HostVolumes
		volumes             []string
		privateIP, publicIP string
	)

	publicIP, err = in.PublicIP(task)
	if err != nil {
		return nil, err
	}
	privateIP, err = in.PrivateIP(task)
	if err != nil {
		return nil, err
	}

	err = in.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		host = clonable.(*abstracts.Host)
		return props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1 = clonable.(*propertiesv1.HostNetwork)
			return props.Inspect(hostproperty.SizingV1, func(clonable data.Clonable) error {
				hostSizingV1 = clonable.(*propertiesv1.HostSizing)
				return props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) error {
					hostVolumesV1 = clonable.(*propertiesv1.HostVolumes)
					volumes = make([]string, len(hostVolumesV1.VolumesByName))
					for _, v := range hostVolumesV1.VolumesByName {
						volumes = append(volumes, v)
					}
					return nil
				})
			})
		})
	})
	if err != nil {
		return nil, err
	}

	return nil, &protocol.Host{
		Cpu:                 int32(hostSizingV1.AllocatedSize.Cores),
		Disk:                int32(hostSizingV1.AllocatedSize.DiskSize),
		GatewayId:           hostNetworkV1.DefaultGatewayID,
		Id:                  in.ID(),
		PublicIp:            publicIP,
		PrivateIp:           PrivateIP,
		Name:                in.Name(),
		PrivateKey:          host.PrivateKey,
		Password:            host.Password,
		Ram:                 hostSizingV1.AllocatedSize.RAMSize,
		State:               protocol.HostState(in.LastState),
		AttachedVolumeNames: volumes,
	}
}

var hostCache struct {
	lock   sync.Mutex
	ByID   utils.Cache
	ByName utils.Cache
}

func init() {
	hostCache.ByID = utils.NewMapCache()
	hostCache.ByName = utils.NewMapCache()
}
