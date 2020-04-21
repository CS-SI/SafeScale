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
	"os"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// hostsFolderName is the technical name of the container used to store networks info
	hostsFolderName = "hosts"
)

// host ...
// follows interface resources.Host
type host struct {
	*core

	installMethods                map[uint8]installmethod.Enum
	privateIP, publicIP, accessIP string
	sshProfile                    *system.SSHConfig
}

// NewHost ...
func NewHost(svc iaas.Service) (resources.Host, error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}

	core, err := NewCore(svc, "host", hostsFolderName, &abstract.HostCore{})
	if err != nil {
		return nil, err
	}

	return &host{core: core}, nil
}

// nullHost returns a *host corresponding to NullValue
func nullHost() *host {
	return &host{core: nullCore()}
}

// LoadHost ...
func LoadHost(task concurrency.Task, svc iaas.Service, ref string) (_ resources.Host, err error) {
	if task == nil {
		return nullHost(), scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nullHost(), scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nullHost(), scerr.InvalidParameterError("ref", "cannot be empty string")
	}
	defer scerr.OnPanic(&err)()

	rh, err := NewHost(svc)
	if err != nil {
		return nullHost(), err
	}

	err = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return rh.Read(task, ref)
		},
		10*time.Second,
	)
	if err != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := err.(retry.ErrTimeout); ok {
			logrus.Debugf("timeout reading metadata of host '%s'", ref)
			err = scerr.NotFoundError("timeout trying to read metadata")
		}
		return nullHost(), err
	}

	return rh, rh.(*host).cacheAccessInformation(task)
}

func (rh *host) cacheAccessInformation(task concurrency.Task) error {
	svc := rh.SafeGetService()

	rh.SafeLock(task)
	defer rh.SafeUnlock(task)

	return rh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		var primaryGatewayConfig, secondaryGatewayConfig *system.SSHConfig

		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return scerr.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		innerErr := props.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if len(hostNetworkV1.IPv4Addresses) > 0 {
				rh.privateIP = hostNetworkV1.IPv4Addresses[hostNetworkV1.DefaultNetworkID]
				if rh.privateIP == "" {
					rh.privateIP = hostNetworkV1.IPv6Addresses[hostNetworkV1.DefaultNetworkID]
				}
			}
			rh.publicIP = hostNetworkV1.PublicIPv4
			if rh.publicIP == "" {
				rh.publicIP = hostNetworkV1.PublicIPv6
			}
			if rh.publicIP != "" {
				rh.accessIP = rh.publicIP
			} else {
				rh.accessIP = rh.privateIP
			}

			if !hostNetworkV1.IsGateway {
				objn, err := LoadNetwork(task, svc, hostNetworkV1.DefaultNetworkID)
				if err != nil {
					return err
				}
				objgw, err := objn.GetGateway(task, true)
				if err != nil {
					return err
				}
				gwErr := objgw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
					gwahc, ok := clonable.(*abstract.HostCore)
					if !ok {
						return scerr.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					ip := objgw.SafeGetAccessIP(task)
					primaryGatewayConfig = &system.SSHConfig{
						PrivateKey: gwahc.PrivateKey,
						Port:       22,
						Host:       ip,
						User:       abstract.DefaultUser,
					}
					return nil
				})
				if gwErr != nil {
					return gwErr
				}

				// Secondary gateway may not exist...
				objgw, err = objn.GetGateway(task, false)
				if err != nil {
					if _, ok := err.(scerr.ErrNotFound); !ok {
						return err
					}
				} else {
					gwErr = objgw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
						gwahc, ok := clonable.(*abstract.HostCore)
						if !ok {
							return scerr.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						secondaryGatewayConfig = &system.SSHConfig{
							PrivateKey: gwahc.PrivateKey,
							Port:       22,
							Host:       objgw.SafeGetAccessIP(task),
							User:       abstract.DefaultUser,
						}
						return nil
					})
					if gwErr != nil {
						return gwErr
					}
				}
			}
			return nil
		})
		if innerErr != nil {
			return innerErr
		}
		rh.sshProfile = &system.SSHConfig{
			Port:                   22,
			Host:                   rh.accessIP,
			User:                   abstract.DefaultUser,
			PrivateKey:             ahc.PrivateKey,
			GatewayConfig:          primaryGatewayConfig,
			SecondaryGatewayConfig: secondaryGatewayConfig,
		}
		return nil
	})
}

func (rh *host) IsNull() bool {
	return rh == nil || rh.core.IsNull()
}

// Browse walks through host folder and executes a callback for each entries
func (rh *host) Browse(task concurrency.Task, callback func(*abstract.HostCore) error) (err error) {
	if rh.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	return rh.core.BrowseFolder(task, func(buf []byte) error {
		ahc := abstract.NewHostCore()
		err = ahc.Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(ahc)
	})
}

// GetState returns the current state of the provider host
func (rh *host) GetState(task concurrency.Task) (hoststate.Enum, error) {
	if rh.IsNull() {
		return hoststate.UNKNOWN, scerr.InvalidInstanceError()
	}
	if rh.IsNull() {
		return hoststate.UNKNOWN, scerr.NotAvailableError("cannot use GetState() on NullHost")
	}

	state := hoststate.UNKNOWN
	err := rh.Reload(task)
	if err != nil {
		return state, err
	}
	err = rh.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		core, ok := clonable.(*abstract.HostCore)
		if !ok {
			return scerr.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		state = core.LastState
		return nil
	})
	return state, err
}

// SafeGetState returns the last state of the host, without forced inspect
func (rh *host) SafeGetState(task concurrency.Task) (state hoststate.Enum) {
	if rh.IsNull() {
		return hoststate.UNKNOWN
	}
	state = hoststate.UNKNOWN
	_ = rh.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		core, ok := clonable.(*abstract.HostCore)
		if !ok {
			return scerr.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		state = core.LastState
		return nil
	})
	return state
}

// Create creates a new host and its metadata
// If the metadata is already carrying a host, returns scerr.ErrNotAvailable
func (rh *host) Create(task concurrency.Task, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements) (_ *userdata.Content, err error) {
	if rh.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if rh.IsNull() {
		return nil, scerr.NotAvailableError("cannot use Create() on NullHost")
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	hostname := rh.SafeGetName()
	if hostname != "" {
		return nil, scerr.NotAvailableError("already carrying host '%s'", hostname)
	}

	tracer := concurrency.NewTracer(task, debug.ShouldTrace("resources.host"), "(%s)", hostReq.ResourceName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError("failed to create host", &err)()
	defer scerr.OnPanic(&err)()

	svc := rh.SafeGetService()

	// Check if host exists and is managed bySafeScale
	_, err = LoadHost(task, svc, hostReq.ResourceName)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return nil, scerr.Wrap(err, "failed to check if it already exists")
		}
	} else {
		return nil, scerr.DuplicateError("already exists")
	}

	// Check if host exists but is not managed by SafeScale
	_, err = svc.GetHostByName(hostReq.ResourceName)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return nil, scerr.Wrap(err, "failed to check if host resource name '%s' is already used", hostReq.ResourceName)
		}
	} else {
		return nil, scerr.DuplicateError("already exists (but not managed by SafeScale)", hostReq.ResourceName)
	}

	// If TemplateID is not explicitly provided, search the appropriate template to satisfy 'hostDef'
	if hostReq.TemplateID == "" {
		useScannerDB := hostDef.MinGPU > 0 || hostDef.MinCPUFreq > 0
		templates, err := svc.SelectTemplatesBySize(hostDef, useScannerDB)
		if err != nil {
			return nil, scerr.Wrap(err, "failed to find template corresponding to requested resources")
		}
		var template abstract.HostTemplate
		if len(templates) > 0 {
			template = *(templates[0])
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
			logrus.Errorf("failed to find template corresponding to requested resources")
			return nil, scerr.Wrap(err, "failed to find template corresponding to requested resources")
		}
		hostReq.TemplateID = template.ID
	}

	var rn resources.Network
	if len(hostReq.Networks) > 0 {
		// By convention, default network is the first of the list
		an := hostReq.Networks[0]
		rn, err = LoadNetwork(task, svc, an.ID)
		if err != nil {
			return nil, err
		}
		if hostReq.DefaultRouteIP == "" {
			hostReq.DefaultRouteIP = rn.SafeGetDefaultRouteIP(task)
		}
	} else {
		rn, _, err = getOrCreateDefaultNetwork(task, svc)
		if err != nil {
			return nil, err
		}
		err = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
			an, ok := clonable.(*abstract.Network)
			if !ok {
				return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostReq.Networks = append(hostReq.Networks, an)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// If hostReq.ImageID is not explicitely defined, find an image ID corresponding to the content of hostDef.Image
	if hostReq.ImageID == "" {
		if hostDef.Image == "" {
			cfg, err := svc.GetConfigurationOptions()
			if err != nil {
				return nil, err
			}
			hostDef.Image = cfg.GetString("DefaultImage")
		}

		var img *abstract.Image
		err = retry.WhileUnsuccessfulDelay1Second(
			func() error {
				var inErr error
				img, inErr = svc.SearchImage(hostDef.Image)
				return inErr
			},
			10*time.Second,
		)
		if err != nil {
			return nil, scerr.Wrap(err, "failed to find image to use on compute resource")
		}
		hostReq.ImageID = img.ID
	}

	hostReq.Password = "safescale" // VPL:for debugging purpose, remove if you see this!
	ahf, userdataContent, err := svc.CreateHost(hostReq)
	if err != nil {
		if _, ok := err.(scerr.ErrInvalidRequest); ok {
			return nil, err
		}
		return nil, scerr.Wrap(err, fmt.Sprintf("failed to create compute resource '%s'", hostReq.ResourceName))
	}

	defer func() {
		if err != nil {
			derr := svc.DeleteHost(ahf.Core.ID)
			if derr != nil {
				logrus.Errorf("cleaning up after failure, failed to delete host '%s': %v", ahf.Core.Name, derr)
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Creates metadata early to "reserve" host name
	err = rh.Carry(task, ahf.Core)
	if err != nil {
		return nil, err
	}

	// Updates properties in metadata
	err = rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		innerErr := props.Alter(task, hostproperty.SizingV2, func(clonable data.Clonable) error {
			hostSizingV2, ok := clonable.(*propertiesv2.HostSizing)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostSizingV2.AllocatedSize = converters.HostEffectiveSizingFromAbstractToPropertyV2(ahf.Sizing)
			hostSizingV2.RequestedSize = converters.HostSizingRequirementsFromAbstractToPropertyV2(hostDef)
			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		// Starting from here, delete host metadata if exiting with error
		defer func() {
			if innerErr != nil {
				derr := rh.core.Delete(task)
				if derr != nil {
					logrus.Errorf("cleaning up after failure, failed to remove host metadata")
				}
			}
		}()

		// Sets host extension DescriptionV1
		innerErr = props.Alter(task, hostproperty.DescriptionV1, func(clonable data.Clonable) error {
			hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_ = hostDescriptionV1.Replace(converters.HostDescriptionFromAbstractToPropertyV1(*ahf.Description))
			creator := ""
			hostname, _ := os.Hostname()
			if curUser, err := user.Current(); err == nil {
				creator = curUser.Username
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
		return props.Alter(task, hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_ = hostNetworkV1.Replace(converters.HostNetworkFromAbstractToPropertyV1(*ahf.Network))
			hostNetworkV1.DefaultNetworkID = rn.SafeGetID()
			hostNetworkV1.IsGateway = hostReq.DefaultRouteIP == "" && rn.SafeGetName() != abstract.SingleHostNetworkName
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	err = rh.cacheAccessInformation(task)
	if err != nil {
		return nil, err
	}

	logrus.Infof("Compute resource created: '%s'", rh.SafeGetName())

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	logrus.Infof("Waiting start of SSH service on remote host '%s' ...", rh.SafeGetName())

	// TODO: configurable timeout here
	status, err := rh.waitInstallPhase(task, userdata.PHASE1_INIT)
	if err != nil {
		if _, ok := err.(scerr.ErrTimeout); ok {
			return nil, scerr.Wrap(err, "Timeout creating a host")
		}
		if abstract.IsProvisioningError(err) {
			logrus.Errorf("%+v", err)
			return nil, scerr.Wrap(err, "error provisioning the new host, please check safescaled logs", rh.SafeGetName())
		}
		return nil, err
	}

	// -- update host property propertiesv1.HostSystem --
	err = rh.Alter(task, func(clonable data.Clonable, properties *serialize.JSONProperties) error {
		return properties.Alter(task, hostproperty.SystemV1, func(clonable data.Clonable) error {
			systemV1, ok := clonable.(*propertiesv1.HostSystem)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostSystem' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			parts := strings.Split(status, ",")
			systemV1.Type = parts[1]
			systemV1.Flavor = parts[2]
			systemV1.Image = hostReq.ImageID
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	// -- Updates host link with networks --
	for _, rn := range hostReq.Networks {
		err := rh.updateNetwork(task, rn.ID)
		if err != nil {
			return nil, err
		}
	}

	// Executes userdata.PHASE2_NETWORK_AND_SECURITY script to configure network and security
	err = rh.runInstallPhase(task, userdata.PHASE2_NETWORK_AND_SECURITY, userdataContent)
	if err != nil {
		return nil, err
	}

	// Reboot host
	command := "sudo systemctl reboot"
	_, _, _, err = rh.Run(task, command, outputs.COLLECT, 0, 0)
	if err != nil {
		return nil, err
	}

	// if host is a gateway, executes userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY script to configure network and security
	if !hostReq.IsGateway {
		// execute userdata.PHASE4_SYSTEM_FIXES script to fix possible misconfiguration in system
		err = rh.runInstallPhase(task, userdata.PHASE4_SYSTEM_FIXES, userdataContent)
		if err != nil {
			return nil, err
		}

		// Reboot host
		command = "sudo systemctl reboot"
		_, _, _, err = rh.Run(task, command, outputs.COLLECT, 0, 0)
		if err != nil {
			return nil, err
		}

		// execute userdata.PHASE5_FINAL script to final install/configure of the host (no need to reboot)
		err = rh.runInstallPhase(task, userdata.PHASE5_FINAL, userdataContent)
		if err != nil {
			return nil, err
		}

		// TODO: configurable timeout here
		status, err = rh.waitInstallPhase(task, userdata.PHASE5_FINAL)
		if err != nil {
			if _, ok := err.(scerr.ErrTimeout); ok {
				return nil, scerr.Wrap(err, "Timeout creating a host")
			}
			if abstract.IsProvisioningError(err) {
				logrus.Errorf("%+v", err)
				return nil, scerr.Wrap(err, "error provisioning the new host, please check safescaled logs", rh.SafeGetName())
			}
			return nil, err
		}
	} else {
		// TODO: configurable timeout here
		status, err = rh.waitInstallPhase(task, userdata.PHASE2_NETWORK_AND_SECURITY)
		if err != nil {
			if _, ok := err.(scerr.ErrTimeout); ok {
				return nil, scerr.Wrap(err, "Timeout creating a host")
			}
			if abstract.IsProvisioningError(err) {
				logrus.Errorf("%+v", err)
				return nil, scerr.Wrap(err, "error provisioning the new host, please check safescaled logs", rh.SafeGetName())
			}
			return nil, err
		}
	}

	logrus.Infof("host '%s' created successfully", rh.SafeGetName())
	return userdataContent, nil
}

func (rh *host) runInstallPhase(task concurrency.Task, phase userdata.Phase, userdataContent *userdata.Content) error {
	// execute userdata 'final' (phase4) script to final install/configure of the host (no need to reboot)
	content, err := userdataContent.Generate(phase)
	if err != nil {
		return err
	}
	file := fmt.Sprintf("/opt/safescale/var/tmp/user_data.%s.sh", phase)
	err = rh.PushStringToFile(task, string(content), file, "", "")
	if err != nil {
		return err
	}
	command := fmt.Sprintf("sudo bash %s; exit $?", file)
	// Executes the script on the remote host
	retcode, _, stderr, err := rh.Run(task, command, outputs.COLLECT, 0, 0)
	if err != nil {
		return err
	}

	if retcode != 0 {
		return scerr.NewError("failed to execute install phase '%s' on host '%s': %s", phase, rh.SafeGetName(), stderr)
	}
	return nil
}

func (rh *host) waitInstallPhase(task concurrency.Task, phase userdata.Phase) (string, error) {
	sshDefaultTimeout := int(temporal.GetHostTimeout().Minutes())
	if sshDefaultTimeoutCandidate := os.Getenv("SSH_TIMEOUT"); sshDefaultTimeoutCandidate != "" {
		num, err := strconv.Atoi(sshDefaultTimeoutCandidate)
		if err == nil {
			logrus.Debugf("Using custom timeout of %d minutes", num)
			sshDefaultTimeout = num
		}
	}
	sshCfg, err := rh.GetSSHConfig(task)
	if err != nil {
		return "", err
	}

	// TODO: configurable timeout here
	status, err := sshCfg.WaitServerReady(task, string(phase), time.Duration(sshDefaultTimeout)*time.Minute)
	if err != nil {
		if _, ok := err.(scerr.ErrTimeout); ok {
			return status, scerr.Wrap(err, "Timeout creating a host")
		}
		if abstract.IsProvisioningError(err) {
			logrus.Errorf("%+v", err)
			return status, scerr.Wrap(err, "error creating host '%s': error provisioning the new host, please check safescaled logs", rh.SafeGetName())
		}
		return status, err
	}
	return status, nil
}

func (rh *host) updateNetwork(task concurrency.Task, networkID string) error {
	objn, err := LoadNetwork(task, rh.core.SafeGetService(), networkID)
	if err != nil {
		return err
	}
	return objn.Alter(task, func(clonable data.Clonable, properties *serialize.JSONProperties) error {
		return properties.Alter(task, networkproperty.HostsV1, func(clonable data.Clonable) error {
			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			id := rh.SafeGetID()
			name := rh.SafeGetName()
			networkHostsV1.ByName[name] = id
			networkHostsV1.ByID[id] = name
			return nil
		})
	})
}

// WaitSSHReady waits until SSH responds successfully
func (rh *host) WaitSSHReady(task concurrency.Task, timeout time.Duration) (status string, err error) {
	if rh.IsNull() {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	return rh.waitInstallPhase(task, userdata.PHASE5_FINAL)
}

// getOrCreateDefaultNetwork gets network abstract.SingleHostNetworkName or create it if necessary
// We don't want metadata on this network, so we use directly provider api instead of services
func getOrCreateDefaultNetwork(task concurrency.Task, svc iaas.Service) (resources.Network, resources.Host, error) {
	if objn, err := LoadNetwork(task, svc, abstract.SingleHostNetworkName); err == nil {
		objpgw, err := objn.GetGateway(task, true)
		if err != nil {
			return nil, nil, err
		}
		return objn, objpgw, nil
	}

	objn, err := NewNetwork(svc)
	if err != nil {
		return nil, nil, err
	}

	request := abstract.NetworkRequest{
		Name:      abstract.SingleHostNetworkName,
		IPVersion: ipversion.IPv4,
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

	objpgw, err := objn.GetGateway(task, true)
	if err != nil {
		return nil, nil, err
	}
	return objn, objpgw, nil
}

// Delete deletes a host with its metadata and updates network links
func (rh *host) Delete(task concurrency.Task) error {
	if rh.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	// rh.SafeLock(task)
	// defer rh.SafeUnlock(task)

	svc := rh.SafeGetService()

	hostID := rh.SafeGetID()
	err := rh.Alter(task, func(_ data.Clonable, properties *serialize.JSONProperties) error {
		// Don't remove a host having shares that are currently remotely mounted
		var shares map[string]*propertiesv1.HostShare
		inErr := properties.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) error {
			sharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			shares = sharesV1.ByID
			shareCount := len(shares)
			for _, hostShare := range shares {
				count := len(hostShare.ClientsByID)
				if count > 0 {
					// clients found, checks if these clients already exists...
					for _, hostID := range hostShare.ClientsByID {
						_, inErr := LoadHost(task, svc, hostID)
						if inErr == nil {
							return scerr.NotAvailableError("exports %d share%s and at least one share is mounted", shareCount, strprocess.Plural(uint(shareCount)))
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
		inErr = properties.Inspect(task, hostproperty.VolumesV1, func(clonable data.Clonable) error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			nAttached := len(hostVolumesV1.VolumesByID)
			if nAttached > 0 {
				return scerr.NotAvailableError("host has %d volume%s attached", nAttached, strprocess.Plural(uint(nAttached)))
			}
			return nil
		})
		if inErr != nil {
			return inErr
		}

		// Don't remove a host that is a gateway
		inErr = properties.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if hostNetworkV1.IsGateway {
				return scerr.NotAvailableError("cannot delete host, it's a gateway that can only be deleted through its network")
			}
			return nil
		})
		if inErr != nil {
			return inErr
		}

		// If host mounted shares, unmounts them before anything else
		var mounts []*propertiesv1.HostShare
		inErr = properties.Inspect(task, hostproperty.MountsV1, func(clonable data.Clonable) error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
				objserver, loopErr := objs.GetServer(task)
				if loopErr != nil {
					return loopErr
				}
				// Retrieve data about share from its server
				share, loopErr := objserver.GetShare(task, i.ShareID)
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

		// Unmounts tier shares mounted on host (done outside the previous host.properties.Reading() section, because
		// Unmount() have to lock for write, and won't succeed while host.properties.Reading() is running,
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
			objs, loopErr := LoadShare(task, svc, share.Name)
			if loopErr != nil {
				return loopErr
			}
			loopErr = objs.Delete(task)
			if loopErr != nil {
				return loopErr
			}
		}

		// Update networks property prosv1.NetworkHosts to remove the reference to the host
		inErr = properties.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostID := rh.SafeGetID()
			hostName := rh.SafeGetName()
			errors := []error{}
			for k := range hostNetworkV1.NetworksByID {
				objn, loopErr := LoadNetwork(task, svc, k)
				if loopErr != nil {
					logrus.Errorf(loopErr.Error())
					errors = append(errors, loopErr)
					continue
				}
				loopErr = objn.Alter(task, func(_ data.Clonable, netprops *serialize.JSONProperties) error {
					return netprops.Alter(task, networkproperty.HostsV1, func(clonable data.Clonable) error {
						networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
						if !ok {
							return scerr.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
					if state, stateErr := svc.GetHostState(rh.SafeGetID()); stateErr == nil {
						logrus.Warnf("While deleting the status was [%s]", state)
						if state == hoststate.ERROR {
							return scerr.NotAvailableError("host is in state ERROR")
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
	err = rh.core.Delete(task)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			// If entry not found, consider a success
			return nil
		}
		return err
	}

	newHost := nullHost()
	*rh = *newHost
	return nil
}

// GetSSHConfig loads SSH configuration for host from metadata
//
// FIXME: system.SSHConfig should be able to carry data about secondary Gateway
//        Currently, if primary gateway is down, ssh to a host in the network will fail
func (rh *host) GetSSHConfig(task concurrency.Task) (_ *system.SSHConfig, err error) {
	if rh.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	rh.SafeRLock(task)
	defer rh.SafeRUnlock(task)
	return rh.sshProfile, nil
}

// Run tries to execute command 'cmd' on the host
func (rh *host) Run(task concurrency.Task, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (int, string, string, error) {
	if rh.IsNull() {
		return 0, "", "", scerr.InvalidInstanceError()
	}
	if task == nil {
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
	ssh, err := rh.GetSSHConfig(task)
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

	hostName := rh.SafeGetName()
	err = retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			retCode, stdOut, stdErr, err = run(task, ssh, cmd, outs, executionTimeout)
			return err
		},
		connectionTimeout,
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Printf("Remote SSH service on host '%s' isn't ready, retrying...", hostName)
			}
		},
	)
	return retCode, stdOut, stdErr, err
}

// run executes command on the host
func run(task concurrency.Task, ssh *system.SSHConfig, cmd string, outs outputs.Enum, timeout time.Duration) (int, string, string, error) {
	// Create the command
	sshCmd, err := ssh.Command(task, cmd)
	if err != nil {
		return 0, "", "", err
	}

	retcode, stdout, stderr, err := sshCmd.RunWithTimeout(task, outs, timeout)
	if err != nil {
		return -1, "", "", err
	}
	// If retcode == 255, ssh connection failed
	if retcode == 255 {
		return -1, "", "", scerr.NewError("failed to connect")
	}
	return retcode, stdout, stderr, err
}

// Pull downloads a file from host
func (rh *host) Pull(task concurrency.Task, target, source string, timeout time.Duration) (int, string, string, error) {
	if rh.IsNull() {
		return 0, "", "", scerr.InvalidInstanceError()
	}
	if source == "" {
		return 0, "", "", scerr.InvalidParameterError("source", "cannot be empty string")
	}
	if target == "" {
		return 0, "", "", scerr.InvalidParameterError("target", "cannot be empty string")
	}

	// retrieve ssh config to perform some commands
	ssh, err := rh.GetSSHConfig(task)
	if err != nil {
		return 0, "", "", err
	}

	// FIXME: reintroduce timeout on ssh.
	// if timeout < temporal.GetHostTimeout() {
	// 	timeout = temporal.GetHostTimeout()
	// }
	return ssh.Copy(task, target, source, false)
}

// Push uploads a file to host
func (rh *host) Push(task concurrency.Task, source, target, owner, mode string, timeout time.Duration) (int, string, string, error) {
	if rh.IsNull() {
		return 0, "", "", scerr.InvalidInstanceError()
	}
	if source == "" {
		return 0, "", "", scerr.InvalidParameterError("source", "cannot be empty string")
	}
	if target == "" {
		return 0, "", "", scerr.InvalidParameterError("target", "cannot be empty string")
	}

	// retrieve ssh config to perform some commands
	ssh, err := rh.GetSSHConfig(task)
	if err != nil {
		return 0, "", "", err
	}

	if timeout < temporal.GetHostTimeout() {
		timeout = temporal.GetHostTimeout()
	}

	retcode, stdout, stderr, err := ssh.Copy(task, target, source, true)
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
		retcode, stdout, stderr, err = run(task, ssh, cmd, outputs.DISPLAY, timeout)
	}
	return retcode, stdout, stderr, err
}

// GetShare returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
func (rh *host) GetShare(task concurrency.Task, shareRef string) (*propertiesv1.HostShare, error) {
	if rh.IsNull() {
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
	err := rh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		// rh, ok := clonable.(*abstract.Host)
		// if !ok {
		// 	return scerr.InconsistentError("'*abstract.Host' expected, '%s' provided", reflect.TypeOf(clonable).String()
		// }
		// props, inErr := rh.properties(task)
		// if inErr != nil {
		// 	return inErr
		// }
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) error {
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
			return scerr.NotFoundError("share '%s' not found in server '%s' metadata", shareRef, rh.SafeGetName())
		})
	})
	if err != nil {
		return nil, err
	}

	return hostShare, nil
}

// GetVolumes returns information about volumes attached to the host
func (rh *host) GetVolumes(task concurrency.Task) (*propertiesv1.HostVolumes, error) {
	if rh.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	var hvV1 *propertiesv1.HostVolumes
	err := rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(task, hostproperty.VolumesV1, func(clonable data.Clonable) error {
			var ok bool
			hvV1, ok = clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.Volumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return hvV1, nil
}

// SafeGetVolumes returns information about volumes attached to the host
func (rh *host) SafeGetVolumes(task concurrency.Task) *propertiesv1.HostVolumes {
	out, _ := rh.GetVolumes(task)
	return out
}

// // GetAttachedVolume returns information about where and how the volume referenced is attached to the host
// func (objh *host) GetAttachedVolume(task concurrency.Task, volumeRef string) (*propertiesv1.HostLocalMount, error) {
// 	if objh.IsNUll() {
// 		return nil, scerr.InvalidInstanceError()
// 	}
// 	if task == nil {
// 		return nil, scerr.InvalidParameterError("task", "cannot be nil")
// 	}
// 	if volumeRef == "" {
// 		return nil, scerr.InvalidParameterError("volumeRef", "cannot be empty string")
// 	}

// 	var mount *propertiesv1.HostMount
// 	err := objh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
// 		var hostVolume *propertiesv1.HostVolume
// 		innerErr := props.Inspect(hostproperty.HostVolumesV1, func(clonable data.Clonable) error {
// 			vaV1, ok := clonable.(*propertiesv1.HostVolumes)
// 			if !ok {
// 				return scerr.InconsistentError("'*propertiesv1.HostVolumess' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 			}
// 			hostVolume, ok = vaV1.VolumesByID[volumeRef]
// 			if !ok {
// 				var ref string
// 				ref, ok = vaV1.VolumesByName[volumeRef]
// 				hostVolume, ok = vaV1.VolumesByID[ref]
// 			}
// 			if !ok {
// 				return scerr.NotFoundError("failed to find a volume referenced by '%s' attached to host '%s'", volumeRef, objh.SafeGetName())
// 			}
// 			return nil
// 		})
// 		if innerErr != nil {
// 			return innerErr
// 		}

// 		return props.Inspect(hostproperty.HostLocalMountV1, func(clonable data.Clonable) error {
// 			hlmV1, ok := clonable.(*propertiesv1.HostLocalMount)
// 			if !ok {
// 				return scerr.InconsistentError("'*propertiesv1.HostMount' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 			}
// 			mount, ok := hlmV1.ByDevice[hostVolume.Device]
// 			return nil
// 		})
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return mount, nil
// }

// Start starts the host
func (rh *host) Start(task concurrency.Task) (err error) {
	if rh.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	scerr.OnPanic(&err)()

	hostName := rh.SafeGetName()
	hostID := rh.SafeGetID()

	svc := rh.SafeGetService()
	err = svc.StartHost(hostID)
	if err != nil {
		return err
	}

	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			return svc.WaitHostState(hostID, hoststate.STARTED, temporal.GetHostTimeout())
		},
		5*time.Minute,
	)
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("timeout waiting host '%s' to be started", hostName))
	}
	return nil
}

// Stop stops the host
func (rh *host) Stop(task concurrency.Task) (err error) {
	if rh.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	hostName := rh.SafeGetName()
	hostID := rh.SafeGetID()

	svc := rh.SafeGetService()
	err = svc.StopHost(hostID)
	if err != nil {
		return err
	}

	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			return svc.WaitHostState(hostID, hoststate.STOPPED, temporal.GetHostTimeout())
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
func (rh *host) Reboot(task concurrency.Task) error {
	err := rh.Stop(task)
	if err != nil {
		return err
	}
	return rh.Start(task)
}

// Resize ...
// not yet implemented
func (rh *host) Resize(hostSize abstract.HostSizingRequirements) error {
	if rh.IsNull() {
		return scerr.InvalidInstanceError()
	}
	return scerr.NotImplementedError("Host.Resize() not yet implemented")
}

// AddFeature handles 'safescale host add-feature <host name or id> <feature name>'
func (rh *host) AddFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (outcomes resources.Results, err error) {
	if rh.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, false /*Trace.Host*/, "(%s)", name).Entering()
	defer tracer.OnExitTrace()()

	feat, err := NewFeature(task, name)
	if err != nil {
		return nil, err
	}
	err = rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		var innerErr error
		outcomes, innerErr = feat.Add(rh, vars, settings)
		if innerErr != nil {
			return innerErr
		}

		// updates HostFeatures property for host
		return props.Alter(task, hostproperty.FeaturesV1, func(clonable data.Clonable) error {
			hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return scerr.InconsistentError("expected '*propertiesv1.HostFeatures', received '%s'", reflect.TypeOf(clonable))
			}
			requires, innerErr := feat.GetRequirements()
			if innerErr != nil {
				return innerErr
			}
			hostFeaturesV1.Installed[name] = &propertiesv1.HostInstalledFeature{
				HostContext: true,
				Requires:    requires,
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return outcomes, nil
}

// CheckFeature ...
func (rh *host) CheckFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, error) {
	if rh.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("featureName", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, false /*Trace.Host, t*/, "(%s)", name).Entering()
	defer tracer.OnExitTrace()()

	feat, err := NewFeature(task, name)
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

	return feat.Check(rh, vars, settings)
}

// DeleteFeature handles 'safescale host delete-feature <host name> <feature name>'
func (rh *host) DeleteFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, error) {
	if rh.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("featureName", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, false /*Trace.Host, */, "(%s)", name).Entering()
	defer tracer.OnExitTrace()

	feat, err := NewFeature(task, name)
	if err != nil {
		return nil, err
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

	err = rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		outcomes, innerErr := feat.Remove(rh, vars, settings)
		if innerErr != nil {
			return scerr.NewError(innerErr, nil, "error uninstalling feature '%s' on '%s'", name, rh.SafeGetName())
		}
		if !outcomes.Successful() {
			msg := fmt.Sprintf("failed to delete feature '%s' from host '%s'", name, rh.SafeGetName())
			tracer.Trace(strprocess.Capitalize(msg) + ":\n" + outcomes.AllErrorMessages())
			return scerr.NewError(msg)
		}

		// updates HostFeatures property for host
		return props.Alter(task, hostproperty.FeaturesV1, func(clonable data.Clonable) error {
			hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return scerr.InconsistentError("expected '*propertiesv1.HostFeatures', received '%s'", reflect.TypeOf(clonable))
			}
			delete(hostFeaturesV1.Installed, name)
			return nil
		})
	})
	return nil, err
}

// GetTargetType returns the type of the target.
// To be used when rh is notoriously not nil.
// satisfies install.Targetable interface.
func (rh *host) SafeGetTargetType() featuretargettype.Enum {
	if rh.IsNull() {
		return featuretargettype.UNKNOWN
	}
	return featuretargettype.HOST
}

// GetPublicIP returns the public IP address of the host
func (rh *host) GetPublicIP(task concurrency.Task) (ip string, err error) {
	ip = ""
	if rh.IsNull() {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	rh.SafeRLock(task)
	defer rh.SafeRUnlock(task)
	return rh.publicIP, nil
}

// SafeGetPublicIP returns the public IP address of the host
// To be used when rh is notoriously not nil
func (rh *host) SafeGetPublicIP(task concurrency.Task) string {
	ip, _ := rh.GetPublicIP(task)
	return ip
}

// GetPrivateIP returns the private IP of the host on its default Network
func (rh *host) GetPrivateIP(task concurrency.Task) (ip string, err error) {
	ip = ""

	rh.SafeRLock(task)
	defer rh.SafeRUnlock(task)
	return rh.privateIP, nil
}

// SafeGetPrivateIP returns the private IP of the host on its default Network
// To be used when rh is notoriously not nil
func (rh *host) SafeGetPrivateIP(task concurrency.Task) string {
	ip, _ := rh.GetPrivateIP(task)
	return ip
}

// GetPrivateIPOnNetwork returns the private IP of the host on its default Network
func (rh *host) GetPrivateIPOnNetwork(task concurrency.Task, networkID string) (ip string, err error) {
	ip = ""
	if rh.IsNull() {
		return ip, scerr.InvalidInstanceError()
	}
	if task == nil {
		return ip, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if networkID == "" {
		return ip, scerr.InvalidParameterError("networkID", "cannot be empty string")
	}

	defer scerr.OnPanic(&err)()

	err = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if ip, ok = hostNetworkV1.IPv4Addresses[networkID]; !ok {
				return scerr.InvalidRequestError("host '%s' does not have an IP address on network '%s'", rh.SafeGetName(), networkID)
			}
			return nil
		})
	})
	return ip, err
}

// SafeGetPrivateIPOnNetwork returns the private IP of the host on its default Network
// To be used when rh is notoriously not nil
func (rh *host) SafeGetPrivateIPOnNetwork(task concurrency.Task, networkID string) string {
	ip, _ := rh.GetPrivateIPOnNetwork(task, networkID)
	return ip
}

// GetAccessIP returns the IP to reach the host
func (rh *host) GetAccessIP(task concurrency.Task) (ip string, err error) {
	ip = ""
	if rh.IsNull() {
		return ip, scerr.InvalidInstanceError()
	}
	if task == nil {
		return ip, scerr.InvalidParameterError("task", "cannot be nil")
	}

	rh.SafeRLock(task)
	defer rh.SafeRUnlock(task)
	return rh.accessIP, nil
}

// SafeGetAccessIP returns the IP to reach the host
// To be used when rh is notoriously not nil
func (rh *host) SafeGetAccessIP(task concurrency.Task) string {
	ip, _ := rh.GetAccessIP(task)
	return ip
}

// SafeGetInstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
//
// satisfies interface install.Targetable
func (rh *host) SafeGetInstallMethods(task concurrency.Task) map[uint8]installmethod.Enum {
	if rh.IsNull() {
		logrus.Error(scerr.InvalidInstanceError().Error())
		return map[uint8]installmethod.Enum{}
	}
	if task == nil {
		logrus.Error(scerr.InvalidParameterError("task", "cannot be nil").Error())
		return map[uint8]installmethod.Enum{}
	}

	rh.SafeLock(task)
	defer rh.SafeUnlock(task)

	if rh.installMethods == nil {
		rh.installMethods = map[uint8]installmethod.Enum{}

		_ = rh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
			// props, inErr := rh.properties(task)
			// if inErr != nil {
			// 	return inErr
			// }

			// Ignore error in this special case; will fallback to use bash method if cannot determine operating system type and flavor
			var index uint8
			_ = props.Inspect(task, hostproperty.SystemV1, func(clonable data.Clonable) error {
				systemV1, ok := clonable.(*propertiesv1.HostSystem)
				if !ok {
					logrus.Error(scerr.InconsistentError("'*propertiesv1.HostSystem' expected, '%s' provided", reflect.TypeOf(clonable).String()))
				}
				if systemV1.Type == "linux" {
					switch systemV1.Flavor {
					case "centos":
						fallthrough
					case "redhat":
						index++
						rh.installMethods[index] = installmethod.Yum
					case "debian":
						fallthrough
					case "ubuntu":
						index++
						rh.installMethods[index] = installmethod.Apt
					case "fedora":
						index++
						rh.installMethods[index] = installmethod.Dnf
					}
				}
				return nil
			})
			index++
			rh.installMethods[index] = installmethod.Bash
			return nil
		})
	}
	return rh.installMethods
}

// GetShares returns the information about the shares hosted by the host
func (rh *host) GetShares(task concurrency.Task) (shares *propertiesv1.HostShares, err error) {
	shares = nil
	if rh.IsNull() {
		return shares, scerr.InvalidInstanceError()
	}
	if task == nil {
		return shares, scerr.InvalidParameterError("task", "cannot be nil")
	}

	err = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			shares = hostSharesV1
			return nil
		})
	})
	return shares, err
}

// SafeGetShares returns the information about the shares of the host
// Intented to be used when objn is notoriously not nil (because previously checked)
func (rh *host) SafeGetShares(task concurrency.Task) *propertiesv1.HostShares {
	shares, _ := rh.GetShares(task)
	return shares
}

// GetMounts returns the information abouts the mounts of the host
func (rh *host) GetMounts(task concurrency.Task) (mounts *propertiesv1.HostMounts, err error) {
	mounts = nil
	if rh.IsNull() {
		return mounts, scerr.InvalidInstanceError()
	}
	if task == nil {
		return mounts, scerr.InvalidParameterError("task", "cannot be nil")
	}

	err = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			mounts = hostMountsV1
			return nil
		})
	})
	return mounts, err
}

// SafeGetMounts returns the information about the mounts of the host
// Intended to be used when objh is notoriously not nil (because previously checked)
func (rh *host) SafeGetMounts(task concurrency.Task) *propertiesv1.HostMounts {
	mounts, _ := rh.GetMounts(task)
	return mounts
}

// SafeGetInstalledFeatures returns a list of installed features
//
// satisfies interface install.Targetable
func (rh *host) SafeGetInstalledFeatures(task concurrency.Task) []string {
	var list []string
	return list
}

// ComplementFeatureParameters configures parameters that are appropriate for the target
//
// satisfies interface install.Targetable
func (rh *host) ComplementFeatureParameters(task concurrency.Task, v data.Map) error {
	if rh.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if v == nil {
		return scerr.InvalidParameterError("v", "cannot be nil")
	}

	v["Hostname"] = rh.SafeGetName()
	v["HostIP"] = rh.SafeGetPrivateIP(task)
	v["PublicIP"] = rh.SafeGetPublicIP(task)

	if _, ok := v["Username"]; !ok {
		v["Username"] = abstract.DefaultUser
	}

	// FIXME: gateway stuff has to be refactored (2 gateways possible)
	var rn resources.Network
	err := rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) error {
			var innerErr error
			networkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			rn, innerErr = LoadNetwork(task, rh.SafeGetService(), networkV1.DefaultNetworkID)
			if innerErr != nil {
				return innerErr
			}
			return nil
		})
	})
	if err != nil {
		return err
	}

	rgw, innerErr := rn.GetGateway(task, true)
	if innerErr != nil {
		return innerErr
	}
	v["PrimaryGatewayIP"] = rgw.SafeGetPrivateIP(task)
	v["GatewayIP"] = v["PrimaryGatewayIP"] // legacy
	v["PrimaryPublicIP"] = rgw.SafeGetPublicIP(task)

	rgw, innerErr = rn.GetGateway(task, false)
	if innerErr != nil {
		if _, ok := innerErr.(scerr.ErrNotFound); !ok {
			return innerErr
		}
	} else {
		v["SecondaryGatewayIP"] = rgw.SafeGetPrivateIP(task)
		v["SecondaryPublicIP"] = rgw.SafeGetPublicIP(task)
	}

	if v["EndpointIP"], err = rn.GetEndpointIP(task); err != nil {
		return err
	}
	v["PublicIP"] = v["EndpointIP"]
	if v["DefaultRouteIP"], err = rn.GetDefaultRouteIP(task); err != nil {
		return err
	}
	return nil
}

// IsClusterMember returns true if the host is member of a cluster
func (rh *host) IsClusterMember(task concurrency.Task) (yes bool, err error) {
	yes = false
	if rh.IsNull() {
		return yes, scerr.InvalidInstanceError()
	}
	if task == nil {
		return yes, scerr.InvalidParameterError("task", "cannot be nil")
	}

	err = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(task, hostproperty.ClusterMembershipV1, func(clonable data.Clonable) error {
			hostClusterMembershipV1, ok := clonable.(*propertiesv1.HostClusterMembership)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostClusterMembership' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			yes = (hostClusterMembershipV1.Cluster != "")
			return nil
		})
	})
	return yes, err
}

// PushStringToFile creates a file 'filename' on remote 'host' with the content 'content'
func (rh *host) PushStringToFile(task concurrency.Task, content string, filename string, owner, mode string) (err error) {
	if rh.IsNull() {
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

	hostName := rh.SafeGetName()
	f, err := system.CreateTempFileFromString(content, 0600)
	if err != nil {
		return scerr.Wrap(err, "failed to create temporary file")
	}
	to := fmt.Sprintf("%s:%s", hostName, filename)
	deleted := false
	retryErr := retry.WhileUnsuccessful(
		func() error {
			var (
				retcode int
				inErr   error
			)
			retcode, _, _, inErr = rh.Push(task, f.Name(), filename, owner, mode, temporal.GetExecutionTimeout())
			if inErr != nil {
				return inErr
			}
			if retcode != 0 {
				// If retcode == 1 (general copy error), retry. It may be a temporary network incident
				if retcode == 1 && !deleted {
					// File may exist on target, try to remove it
					_, _, _, inErr = rh.Run(task, "sudo rm -f "+filename, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
					if inErr == nil {
						deleted = true
					}
					return scerr.NewError("file may exist on remote with inappropriate access rights, deleted it and retrying")
				}
				if system.IsSCPRetryable(retcode) {
					err = scerr.NewError("failed to copy temporary file to '%s' (retcode: %d=%s)", to, retcode, system.SCPErrorString(retcode))
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
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return scerr.Wrap(retryErr, "timeout trying to copy temporary file to '%s'", to)
		}
		return err
	}

	cmd := ""
	if owner != "" {
		cmd += `sudo chown ` + owner + ` '` + filename + `' ;`
	}
	if mode != "" {
		cmd += `sudo chmod ` + mode + ` '` + filename + `'`
	}
	if cmd != "" {
		retryErr = retry.WhileUnsuccessful(
			func() error {
				var retcode int
				retcode, _, _, err = rh.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
				if err != nil {
					return err
				}
				if retcode != 0 {
					err = scerr.NewError("failed to change rights of file '%s' (retcode=%d)", to, retcode)
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
				return scerr.Wrap(err, "timeout trying to change rights of file '%s' on host '%s'", filename, hostName)
			default:
				return scerr.Wrap(retryErr, "failed to change rights of file '%s' on host '%s'", filename, hostName)
			}
		}
	}
	return nil
}

// GetDefaultNetwork returns the Network instance corresponding to host default network
func (rh *host) GetDefaultNetwork(task concurrency.Task) (objn resources.Network, err error) {
	if rh.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	err = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) error {
			networkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if networkV1.DefaultNetworkID != "" {
				var inErr error
				objn, inErr = LoadNetwork(task, rh.SafeGetService(), networkV1.DefaultNetworkID)
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

// ToProtocol convert an resources.Host to protocol.Host
func (rh *host) ToProtocol(task concurrency.Task) (ph *protocol.Host, err error) {
	if rh == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer scerr.OnPanic(&err)()

	var (
		ahc           *abstract.HostCore
		hostNetworkV1 *propertiesv1.HostNetwork
		hostSizingV1  *propertiesv1.HostSizing
		hostVolumesV1 *propertiesv1.HostVolumes
		volumes       []string
	)

	publicIP := rh.SafeGetPublicIP(task)
	privateIP := rh.SafeGetPrivateIP(task)

	err = rh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		var ok bool
		ahc, ok = clonable.(*abstract.HostCore)
		if !ok {
			return scerr.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		return props.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok = clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String)
			}
			return props.Inspect(task, hostproperty.SizingV1, func(clonable data.Clonable) error {
				hostSizingV1, ok = clonable.(*propertiesv1.HostSizing)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String)
				}
				return props.Inspect(task, hostproperty.VolumesV1, func(clonable data.Clonable) error {
					hostVolumesV1, ok = clonable.(*propertiesv1.HostVolumes)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String)
					}

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
		return ph, err
	}

	ph = &protocol.Host{
		Cpu:                 int32(hostSizingV1.AllocatedSize.Cores),
		Disk:                int32(hostSizingV1.AllocatedSize.DiskSize),
		GatewayId:           hostNetworkV1.DefaultGatewayID,
		Id:                  ahc.ID,
		PublicIp:            publicIP,
		PrivateIp:           privateIP,
		Name:                ahc.Name,
		PrivateKey:          ahc.PrivateKey,
		Password:            ahc.Password,
		Ram:                 hostSizingV1.AllocatedSize.RAMSize,
		State:               protocol.HostState(ahc.LastState),
		AttachedVolumeNames: volumes,
	}
	return ph, nil
}
