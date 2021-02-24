/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// networksFolderName is the technical name of the container used to store networks info
	subnetsFolderName = "subnets"

	subnetInternalSecurityGroupNamePattern        = "safescale-sg_subnet_internals.%s.%s"
	subnetInternalSecurityGroupDescriptionPattern = "SG for internal access in Subnet %s of Network %s"
	subnetGWSecurityGroupNamePattern              = "safescale-sg_subnet_gateways.%s.%s"
	subnetGWSecurityGroupDescriptionPattern       = "SG for gateways in Subnet %s of Network %s"
	subnetPublicIPSecurityGroupNamePattern        = "safescale-sg_subnet_publicip.%s.%s"
	subnetPublicIPSecurityGroupDescriptionPattern = "SG for hosts with public IP in Subnet %s of Network %s"
)

// subnet links Object Storage folder and Subnet
type subnet struct {
	*core

	cacheLock      *sync.Mutex
	cachedGateways [2]*host
	cachedNetwork  *network
}

func nullSubnet() *subnet {
	return &subnet{core: nullCore()}
}

// ListSubnets returns a list of available subnets
func ListSubnets(task concurrency.Task, svc iaas.Service, networkID string, all bool) (_ []*abstract.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	if all {
		return svc.ListSubnets(networkID)
	}

	rs, xerr := NewSubnet(svc)
	if xerr != nil {
		return nil, xerr
	}

	// recover subnets from metadata
	var list []*abstract.Subnet
	xerr = rs.Browse(task, func(as *abstract.Subnet) fail.Error {
		if networkID == "" || as.Network == networkID {
			list = append(list, as)
		}
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return list, nil
}

// NewSubnet creates an instance of subnet used as resources.Subnet
func NewSubnet(svc iaas.Service) (_ resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nullSubnet(), fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := newCore(svc, "subnet", subnetsFolderName, &abstract.Subnet{})
	if xerr != nil {
		return nullSubnet(), xerr
	}

	out := &subnet{
		core:      coreInstance,
		cacheLock: &sync.Mutex{},
	}
	return out, nil
}

// lookupSubnet tells if a Subnet exists
func lookupSubnet(task concurrency.Task, svc iaas.Service, networkRef, subnetRef string) (_ bool, xerr fail.Error) {
	var subnetID string
	if networkRef != "" {
		// If networkRef is not empty, make sure the subnetRef is inside the network
		rn, xerr := LoadNetwork(task, svc, networkRef)
		if xerr != nil {
			return false, xerr
		}

		xerr = rn.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(task, networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
				subnetsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				var found bool
				for k, v := range subnetsV1.ByName {
					if k == subnetRef || v == subnetRef {
						subnetID = v
						found = true
						break
					}
				}
				if !found {
					return fail.NotFoundError("failed to find a Subnet referenced by '%s' in Network '%s'", subnetRef, rn.GetName())
				}
				return nil
			})
		})
		if xerr != nil {
			return false, xerr
		}
	} else {
		// If networkRef is empty, subnetRef must be subnetID
		subnetID = subnetRef
	}

	rs, xerr := NewSubnet(svc)
	if xerr != nil {
		return false, xerr
	}
	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return rs.ReadByID(task, subnetID)
		},
		10*time.Second, // FIXME: parameterize
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return false, nil
		default:
			return false, xerr
		}
	}
	return true, nil
}

// LoadSubnet loads the metadata of a subnet
func LoadSubnet(task concurrency.Task, svc iaas.Service, networkRef, subnetRef string) (rs resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task == nil {
		return nullSubnet(), fail.InvalidParameterCannotBeNilError("task")
	}
	if svc == nil {
		return nullSubnet(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if subnetRef = strings.TrimSpace(subnetRef); subnetRef == "" {
		return nullSubnet(), fail.InvalidParameterError("subnetRef", "cannot be empty string")
	}
	networkRef = strings.TrimSpace(networkRef)

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	var subnetID string
	switch networkRef {
	case "":
		// If networkRef is empty, subnetRef must be subnetID
		subnetID = subnetRef
	default:
		// Try to load Network metadata
		rn, xerr := LoadNetwork(task, svc, networkRef)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Network metadata can be missing if it's the default Network, so continue
			default:
				return nil, xerr
			}
		}
		if rn != nil { //nolint
			// Network metadata loaded, find the ID of the Subnet (subnetRef may be ID or Name)
			xerr = rn.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Inspect(task, networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
					subnetsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					var found bool
					for k, v := range subnetsV1.ByName {
						if k == subnetRef || v == subnetRef {
							subnetID = v
							found = true
							break
						}
					}
					if !found {
						return fail.NotFoundError("failed to find a subnet referenced by '%s' in network '%s'", subnetRef, rn.GetName())
					}
					return nil
				})
			})
			if xerr != nil {
				return nil, xerr
			}
		} else if svc.HasDefaultNetwork() {
			// No Network Metadata, try to use the default Network if there is one
			an, xerr := svc.GetDefaultNetwork()
			if xerr != nil {
				return nil, xerr
			}
			if an.Name == networkRef || an.ID == networkRef {
				// We are in default Network context, query subnet list and search for the one requested
				list, xerr := ListSubnets(task, svc, an.ID, false)
				if xerr != nil {
					return nil, xerr
				}
				for _, v := range list {
					if v.ID == subnetRef || v.Name == subnetRef {
						subnetID = v.ID
						break
					}
				}
			}
		} else {
			// failed to identify the Network owning the Subnets
			return nil, fail.NotFoundError("failed to find Network '%s'", networkRef)
		}
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	if subnetID != "" {
		if rs, xerr = NewSubnet(svc); xerr == nil {
			// TODO: core.Read() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
			xerr = rs.ReadByID(task, subnetID)
		}
	} else {
		xerr = fail.NotFoundError()
	}
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			if networkRef != "" {
				// rewrite NotFoundError, user does not bother about metadata stuff
				return nullSubnet(), fail.NotFoundError("failed to find a Subnet '%s' in Network '%s'", subnetRef, networkRef)
			}
			return nullSubnet(), fail.NotFoundError("failed to find a Subnet referenced by '%s'", subnetRef)
		default:
			return nullSubnet(), xerr
		}
	}

	return rs, nil
}

// IsNull tells if the instance corresponds to subnet Null Value
func (rs *subnet) IsNull() bool {
	return rs == nil || rs.core.IsNull()
}

// Create creates a subnet
// FIXME: split up this function for readability
func (rs *subnet) Create(task concurrency.Task, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"),
		"('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.Image, req.HA,
	).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr)

	rn, an, xerr := rs.validateNetwork(task, &req)
	if xerr != nil {
		return xerr
	}

	// Check if subnet already exists and is managed by SafeScale
	if xerr = rs.checkUnicity(task, req); xerr != nil {
		return xerr
	}

	// Verify the CIDR is not routable
	if xerr = rs.validateCIDR(&req, *an); xerr != nil {
		return fail.Wrap(xerr, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
	}

	// Create the subnet
	svc := rs.GetService()
	as, xerr := svc.CreateSubnet(req)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound, *fail.ErrInvalidRequest, *fail.ErrTimeout:
			return xerr
		default:
			return xerr
		}
	}

	// Starting from here, delete subnet if exiting with error
	defer func() {
		if xerr != nil && as != nil && !req.KeepOnFailure {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := svc.DeleteSubnet(as.ID); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", actionFromError(xerr)))
			}
		}
	}()

	// Write subnet object metadata
	if xerr = rs.Carry(task, as); xerr != nil {
		return xerr
	}

	// Starting from here, delete subnet metadata if exiting with error
	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := rs.core.Delete(task); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete subnet metadata", actionFromError(xerr)))
			}
		}
	}()

	var subnetGWSG, subnetInternalSG, subnetPublicIPSG resources.SecurityGroup
	if subnetGWSG, xerr = rs.createGWSecurityGroup(task, req, *as, *an); xerr != nil {
		return xerr
	}
	defer rs.undoCreateSecurityGroup(task, &xerr, req.KeepOnFailure, subnetGWSG)

	if subnetInternalSG, xerr = rs.createInternalSecurityGroup(task, req, *as, *an); xerr != nil {
		return xerr
	}
	defer rs.undoCreateSecurityGroup(task, &xerr, req.KeepOnFailure, subnetInternalSG)

	if xerr = subnetGWSG.BindToSubnet(task, rs, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark); xerr != nil {
		return xerr
	}

	if subnetPublicIPSG, xerr = rs.createPublicIPSecurityGroup(task, req, *as, *an); xerr != nil {
		return xerr
	}
	defer rs.undoCreateSecurityGroup(task, &xerr, req.KeepOnFailure, subnetPublicIPSG)

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := subnetGWSG.UnbindFromSubnet(task, rs); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group for gateway from subnet", actionFromError(xerr)))
			}
		}
	}()

	if xerr = subnetInternalSG.BindToSubnet(task, rs, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsDefault); xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := subnetInternalSG.UnbindFromSubnet(task, rs); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group for Hosts from Subnet", actionFromError(xerr)))
			}
		}
	}()

	// IDs of Security Groups to attach to IPAddress used as gateway
	sgs := map[string]struct{}{
		subnetGWSG.GetID():       struct{}{},
		subnetInternalSG.GetID(): struct{}{},
		subnetPublicIPSG.GetID(): struct{}{},
	}

	caps := svc.GetCapabilities()
	failover := req.HA
	if failover {
		if caps.PrivateVirtualIP {
			logrus.Info("Driver support private Virtual IP, honoring the failover setup for gateways.")
		} else {
			logrus.Warning("Driver does not support private Virtual IP, cannot set up failover of subnet default route.")
			failover = false
		}
	}

	// Creates VIP for gateways if asked for
	if failover {
		if as.VIP, xerr = svc.CreateVIP(as.Network, as.ID, fmt.Sprintf("for gateways of subnet %s", as.Name), []string{subnetGWSG.GetID()}); xerr != nil {
			return fail.Wrap(xerr, "failed to create VIP")
		}

		// Starting from here, delete VIP if exists with error
		defer func() {
			if xerr != nil && as != nil && as.VIP != nil && !req.KeepOnFailure {
				if derr := svc.DeleteVIP(as.VIP); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete VIP", actionFromError(xerr)))
				}
			}
		}()
	}

	xerr = rs.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		as.State = subnetstate.GATEWAY_CREATION
		as.GWSecurityGroupID = subnetGWSG.GetID()
		as.InternalSecurityGroupID = subnetInternalSG.GetID()
		as.PublicIPSecurityGroupID = subnetPublicIPSG.GetID()

		// Creates the bind between the subnet default security group and the subnet
		return props.Alter(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			item := &propertiesv1.SecurityGroupBond{
				ID:       subnetGWSG.GetID(),
				Name:     subnetGWSG.GetName(),
				Disabled: false,
			}
			ssgV1.ByID[item.ID] = item
			ssgV1.ByName[subnetGWSG.GetName()] = item.ID

			item = &propertiesv1.SecurityGroupBond{
				ID:       subnetInternalSG.GetID(),
				Name:     subnetInternalSG.GetName(),
				Disabled: false,
			}
			ssgV1.ByID[item.ID] = item
			ssgV1.ByName[item.Name] = item.ID
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// attach Subnet to Network, if Network is not default Network (in this case, it has no metadata)
	if rn != nil {
		xerr = rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(task, networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
				nsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				nsV1.ByID[as.ID] = as.Name
				nsV1.ByName[as.Name] = as.ID
				return nil
			})
		})
		if xerr != nil {
			return xerr
		}

		// Starting from here, remove Subnet from Network metadata if exiting with error
		defer func() {
			if xerr != nil && !req.KeepOnFailure {
				// Disable abort signal during clean up
				defer task.DisarmAbortSignal()()

				derr := rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Alter(task, networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
						nsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
						if !ok {
							return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						delete(nsV1.ByID, as.ID)
						delete(nsV1.ByName, as.Name)
						return nil
					})
				})
				if derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to detach Subnet from Network", actionFromError(xerr)))
				}
			}
		}()
	}

	// --- Create the gateway(s) ---

	if gwSizing == nil {
		gwSizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}
	template, xerr := svc.FindTemplateBySizing(*gwSizing)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to find appropriate template")
	}
	// msg := fmt.Sprintf("Selected host template: '%s' (%d core%s", template.Name, template.Cores, strprocess.Plural(uint(template.Cores)))
	// if template.CPUFreq > 0 {
	// 	msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
	// }
	// msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
	// if template.GPUNumber > 0 {
	// 	msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, strprocess.Plural(uint(template.GPUNumber)))
	// 	if template.GPUType != "" {
	// 		msg += fmt.Sprintf(" %s", template.GPUType)
	// 	}
	// }
	// msg += ")"
	// logrus.Infof(msg)

	// define image...
	if gwSizing.Image == "" {
		// if gwSizing.Image != "" {
		gwSizing.Image = req.Image
		// }
	}
	if gwSizing.Image == "" {
		cfg, xerr := svc.GetConfigurationOptions()
		if xerr != nil {
			return xerr
		}
		gwSizing.Image = cfg.GetString("DefaultImage")
	}
	if gwSizing.Image == "" {
		gwSizing.Image = "Ubuntu 18.04"
	}
	if req.Image == "" {
		req.Image = gwSizing.Image
	}

	img, xerr := svc.SearchImage(gwSizing.Image)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to find image '%s'", gwSizing.Image)
	}

	subnetName := rs.GetName()
	var primaryGatewayName, secondaryGatewayName string
	if failover || gwname == "" {
		primaryGatewayName = "gw-" + subnetName
	} else {
		primaryGatewayName = gwname
	}
	if failover {
		secondaryGatewayName = "gw2-" + subnetName
	}

	domain := strings.Trim(req.Domain, ".")
	if domain != "" {
		domain = "." + domain
	}
	//
	// keypairName := "kp_" + subnetName
	// keypair, xerr := svc.CreateKeyPair(keypairName)
	// if xerr != nil {
	// 	return xerr
	// }

	keepalivedPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return fail.ToError(err)
	}

	gwRequest := abstract.HostRequest{
		ImageID: img.ID,
		Subnets: []*abstract.Subnet{as},
		// KeyPair:          keypair,
		SSHPort:          req.DefaultSSHPort,
		TemplateID:       template.ID,
		KeepOnFailure:    req.KeepOnFailure,
		SecurityGroupIDs: sgs,
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
	primaryTask, xerr = task.StartInSubtask(rs.taskCreateGateway, taskCreateGatewayParameters{
		request: primaryRequest,
		sizing:  *gwSizing,
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
		secondaryTask, xerr = task.StartInSubtask(rs.taskCreateGateway, taskCreateGatewayParameters{
			request: secondaryRequest,
			sizing:  *gwSizing,
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
				// Disable abort signal during clean up
				defer task.DisarmAbortSignal()()

				logrus.Debugf("Cleaning up on failure, deleting gateway '%s'...", primaryGateway.GetName())
				if derr := primaryGateway.relaxedDeleteHost(task); xerr != nil {
					switch derr.(type) {
					case *fail.ErrTimeout:
						logrus.Warnf("We should have waited more...") // FIXME: Wait until gateway no longer exists
					default:
					}
					_ = xerr.AddConsequence(derr)
				} else {
					logrus.Debugf("Cleaning up on failure, gateway '%s' deleted", primaryGateway.GetName())
				}
				if failover {
					if derr := rs.unbindHostFromVIP(as.VIP, primaryGateway); derr != nil {
						_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind VIP from gateway", actionFromError(xerr)))
					}
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
					// Disable abort signal during clean up
					defer task.DisarmAbortSignal()()

					if derr := secondaryGateway.relaxedDeleteHost(task); xerr != nil {
						switch derr.(type) {
						case *fail.ErrTimeout:
							logrus.Warnf("We should have waited more") // FIXME: Wait until gateway no longer exists
						default:
						}
						_ = xerr.AddConsequence(derr)
					}
					if derr := rs.unbindHostFromVIP(as.VIP, secondaryGateway); derr != nil {
						_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind VIP from gateway", actionFromError(xerr)))
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

	// Update userdata of gateway(s)
	xerr = rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// Updates userdatas to use later
		primaryUserdata.PrimaryGatewayPrivateIP = primaryGateway.getPrivateIP(task)
		primaryUserdata.PrimaryGatewayPublicIP = primaryGateway.getPublicIP(task)
		primaryUserdata.IsPrimaryGateway = true
		if as.VIP != nil {
			primaryUserdata.DefaultRouteIP = as.VIP.PrivateIP
			primaryUserdata.EndpointIP = as.VIP.PublicIP
		} else {
			primaryUserdata.DefaultRouteIP = primaryUserdata.PrimaryGatewayPrivateIP
			primaryUserdata.EndpointIP = primaryUserdata.PrimaryGatewayPublicIP
		}
		if secondaryGateway != nil {
			// as.SecondaryGatewayID = secondaryGateway.GetID()
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

	// As hosts are marked as gateways, the configuration stopped on phase 2 'netsec', the remaining 3 phases have to be run explicitly
	if primaryTask, xerr = concurrency.NewTask(); xerr != nil {
		return xerr
	}
	xerr = rs.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		as.State = subnetstate.GATEWAY_CONFIGURATION
		return nil
	})
	if xerr != nil {
		return xerr
	}

	primaryTask, xerr = primaryTask.Start(rs.taskFinalizeGatewayConfiguration, taskFinalizeGatewayConfigurationParameters{
		host:     primaryGateway,
		userdata: primaryUserdata,
	})
	if xerr != nil {
		return xerr
	}
	if failover && secondaryTask != nil {
		if secondaryTask, xerr = concurrency.NewTask(); xerr != nil {
			return xerr
		}
		secondaryTask, xerr = secondaryTask.Start(rs.taskFinalizeGatewayConfiguration, taskFinalizeGatewayConfigurationParameters{
			host:     secondaryGateway,
			userdata: secondaryUserdata,
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

	// --- Updates subnet state in metadata ---
	return rs.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		as.State = subnetstate.READY
		return nil
	})
}

// validateCIDR tests if CIDR requested is valid, or select one if no CIDR is provided
func (rs subnet) validateCIDR(req *abstract.SubnetRequest, network abstract.Network) fail.Error {
	_, networkDesc, _ := net.ParseCIDR(network.CIDR)
	if req.CIDR != "" {
		routable, xerr := netutils.IsCIDRRoutable(req.CIDR)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to determine if CIDR is not routable")
		}
		if routable {
			return fail.InvalidRequestError("cannot create such a subnet, CIDR must NOT be routable; please choose an appropriate CIDR (RFC1918)")
		}

		_, subnetDesc, err := net.ParseCIDR(req.CIDR)
		if err != nil {
			return fail.ToError(err)
		}
		// ... and if CIDR is inside VPC's one
		if !netutils.CIDROverlap(*networkDesc, *subnetDesc) {
			return fail.InvalidRequestError("not inside Network CIDR '%s'", req.CIDR, req.Name, network.CIDR)
		}
		return nil
	}

	// CIDR is empty, choose the first Class C available one
	logrus.Debugf("CIDR is empty, choosing one...")

	subnets, xerr := rs.GetService().ListSubnets(network.ID)
	if xerr != nil {
		return xerr
	}
	var (
		newIPNet net.IPNet
		found    bool
	)
	mask, _ := networkDesc.Mask.Size()
	//if mask >= 24 {
	//	bitShift = 1
	//} else {
	//	bitShift = 24 - uint8(mask)
	//}
	maxBitShift := uint(30 - mask)

	for bs := uint(1); bs <= maxBitShift && !found; bs++ {
		limit := uint(1 << maxBitShift)
		for i := uint(1); i <= limit; i++ {
			newIPNet, xerr = netutils.NthIncludedSubnet(*networkDesc, uint8(bs), i)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to choose a CIDR for the subnet")
			}
			if wouldOverlap(subnets, newIPNet) == nil {
				found = true
				break
			}
		}
	}
	if !found {
		return fail.OverflowError(nil, maxBitShift, "failed to find a free available CIDR ")
	}

	req.CIDR = newIPNet.String()
	logrus.Debugf("CIDR chosen for Subnet '%s' is '%s'", req.Name, req.CIDR)
	return nil
}

// wouldOverlap returns fail.ErrOverloadError if subnet overlaps one of the subnets in allSubnets
// TODO: there is room for optimization here, 'allSubnets' is walked through at each call...
func wouldOverlap(allSubnets []*abstract.Subnet, subnet net.IPNet) fail.Error {
	for _, s := range allSubnets {
		_, sDesc, _ := net.ParseCIDR(s.CIDR)
		if netutils.CIDROverlap(subnet, *sDesc) {
			return fail.OverloadError("would intersect with '%s (%s)'", s.Name, s.CIDR)
		}
	}
	return nil
}

// checkUnicity checks if the Subnet name is not already used
func (rs subnet) checkUnicity(task concurrency.Task, req abstract.SubnetRequest) fail.Error {
	svc := rs.GetService()
	if found, xerr := lookupSubnet(task, svc, req.NetworkID, req.Name); xerr == nil && found {
		return fail.DuplicateError("subnet '%s' already exists", req.Name)
	}

	// Verify if the subnet already exist and in this case is not managed by SafeScale
	if _, xerr := svc.InspectSubnetByName(req.NetworkID, req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return xerr
		}
	} else {
		return fail.DuplicateError("subnet '%s' already exists (not managed by SafeScale)", req.Name)
	}

	return nil
}

// validateNetwork verifies the Network exists and make sure req.Network field is an ID
func (rs subnet) validateNetwork(task concurrency.Task, req *abstract.SubnetRequest) (resources.Network, *abstract.Network, fail.Error) {
	var an *abstract.Network
	svc := rs.GetService()
	rn, xerr := LoadNetwork(task, svc, req.NetworkID)
	if xerr == nil {
		xerr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			var ok bool
			an, ok = clonable.(*abstract.Network)
			if !ok {
				return fail.InconsistentError("'*abstract.Networking' expected, %s' provided", reflect.TypeOf(clonable).String())
			}

			// check the network exists on provider side
			if _, innerXErr := svc.InspectNetwork(an.ID); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// TODO: automatic metadata cleanup ?
					return fail.InconsistentError("inconsistent metadata detected for Network '%s': it does not exist anymore on provider side", an.Name)
				default:
					return innerXErr
				}
			}
			return nil
		})
	} else {
		rn = nil
		switch xerr.(type) { //nolint
		case *fail.ErrNotFound:
			if !svc.HasDefaultNetwork() {
				return nil, nil, xerr
			}
			an, xerr = svc.GetDefaultNetwork()
		}
	}
	if xerr != nil {
		return nil, nil, xerr
	}
	req.NetworkID = an.ID
	if len(req.DNSServers) == 0 {
		req.DNSServers = an.DNSServers
	}

	return rn, an, nil
}

// createGWSecurityGroup creates a Security Group to be applied to gateways of the Subnet
func (rs subnet) createGWSecurityGroup(task concurrency.Task, req abstract.SubnetRequest, subnet abstract.Subnet, network abstract.Network) (_ resources.SecurityGroup, xerr fail.Error) {
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetGWSecurityGroupNamePattern, req.Name, network.Name)

	var sg resources.SecurityGroup
	if sg, xerr = NewSecurityGroup(rs.GetService()); xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetGWSecurityGroupDescriptionPattern, req.Name, network.Name)
	if xerr = sg.Create(task, network.ID, sgName, description, nil); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := sg.Delete(task); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", actionFromError(xerr), req.Name))
			}
		}
	}()

	rules := abstract.SecurityGroupRules{
		{
			Description: "[ingress][ipv4][tcp] Allow SSH",
			Direction:   securitygroupruledirection.INGRESS,
			PortFrom:    22,
			EtherType:   ipversion.IPv4,
			Protocol:    "tcp",
			Sources:     []string{"0.0.0.0/0"},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: "[ingress][ipv6][tcp] Allow SSH",
			Direction:   securitygroupruledirection.INGRESS,
			PortFrom:    22,
			EtherType:   ipversion.IPv6,
			Protocol:    "tcp",
			Sources:     []string{"::/0"},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: "[ingress][ipv4][icmp] Allow everything",
			Direction:   securitygroupruledirection.INGRESS,
			EtherType:   ipversion.IPv4,
			Protocol:    "icmp",
			Sources:     []string{"0.0.0.0/0"},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: "[ingress][ipv6][icmp] Allow everything",
			Direction:   securitygroupruledirection.INGRESS,
			EtherType:   ipversion.IPv6,
			Protocol:    "icmp",
			Sources:     []string{"::/0"},
			Targets:     []string{sg.GetID()},
		},
	}
	if xerr = sg.AddRules(task, rules); xerr != nil {
		return nil, xerr
	}

	return sg, nil
}

// createPublicIPSecurityGroup creates a Security Group to be applied to host of the Subnet with public IP that is not a gateway
func (rs subnet) createPublicIPSecurityGroup(task concurrency.Task, req abstract.SubnetRequest, subnet abstract.Subnet, network abstract.Network) (_ resources.SecurityGroup, xerr fail.Error) {
	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetPublicIPSecurityGroupNamePattern, req.Name, network.Name)

	var sg resources.SecurityGroup
	if sg, xerr = NewSecurityGroup(rs.GetService()); xerr != nil {
		return nil, xerr
	}
	description := fmt.Sprintf(subnetPublicIPSecurityGroupDescriptionPattern, req.Name, network.Name)
	xerr = sg.Create(task, network.ID, sgName, description, nil)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := sg.Delete(task); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", actionFromError(xerr), req.Name))
			}
		}
	}()

	rules := abstract.SecurityGroupRules{
		{
			Description: "[egress][ipv4][all] Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			EtherType:   ipversion.IPv4,
			Sources:     []string{sg.GetID()},
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: "[egress][ipv6][all] Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			EtherType:   ipversion.IPv6,
			Sources:     []string{sg.GetID()},
			Targets:     []string{"::0/0"},
		},
	}
	if xerr = sg.AddRules(task, rules); xerr != nil {
		return nil, xerr
	}

	return sg, nil
}

// Starting from here, delete the Security Group if exiting with error
func (rs subnet) undoCreateSecurityGroup(task concurrency.Task, errorPtr *fail.Error, keepOnFailure bool, sg resources.SecurityGroup) {
	if errorPtr == nil {
		logrus.Errorf("trying to cancel an action based on the content of a nil fail.Error; cancel cannot be run")
		return
	}
	if *errorPtr != nil && !keepOnFailure {
		// Disable abort signal during clean up
		defer task.DisarmAbortSignal()()

		sgName := sg.GetName()
		if derr := sg.Delete(task); derr != nil {
			_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove Subnet's Security Group for gateways '%s'", actionFromError(*errorPtr), sgName))
		}
	}
}

// Creates a Security Group to be applied on Hosts in Subnet to allow internal access
func (rs subnet) createInternalSecurityGroup(task concurrency.Task, req abstract.SubnetRequest, subnet abstract.Subnet, network abstract.Network) (_ resources.SecurityGroup, xerr fail.Error) {
	sgName := fmt.Sprintf(subnetInternalSecurityGroupNamePattern, req.Name, network.Name)

	var sg resources.SecurityGroup
	if sg, xerr = NewSecurityGroup(rs.GetService()); xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetInternalSecurityGroupDescriptionPattern, req.Name, network.Name)
	if xerr = sg.Create(task, network.ID, sgName, description, nil); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := sg.Delete(task); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove Subnet's Security Group for gateways '%s'", actionFromError(xerr), req.Name))
			}
		}
	}()

	// adds rules that depends on Security Group ID
	rules := abstract.SecurityGroupRules{
		{
			Description: fmt.Sprintf("[egress][ipv4][all] Allow LAN traffic in %s", req.CIDR),
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.EGRESS,
			Sources:     []string{sg.GetID()},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: fmt.Sprintf("[egress][ipv6][all] Allow LAN traffic in %s", req.CIDR),
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.EGRESS,
			Sources:     []string{sg.GetID()},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: fmt.Sprintf("[ingress][ipv4][all] Allow LAN traffic in %s", req.CIDR),
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.INGRESS,
			Sources:     []string{sg.GetID()},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: fmt.Sprintf("[ingress][ipv6][all] Allow LAN traffic in %s", req.CIDR),
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.INGRESS,
			Sources:     []string{sg.GetID()},
			Targets:     []string{sg.GetID()},
		},
	}
	if xerr = sg.AddRules(task, rules); xerr != nil {
		return nil, xerr
	}

	return sg, nil
}

// unbindHostFromVIP unbinds a VIP from IPAddress
// Actually does nothing in aws for now
func (rs subnet) unbindHostFromVIP(vip *abstract.VirtualIP, host resources.Host) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if xerr := rs.GetService().UnbindHostFromVIP(vip, host.GetID()); xerr != nil {
		return fail.Wrap(xerr, "cleaning up on %s, failed to unbind gateway '%s' from VIP", actionFromError(xerr), host.GetName())
	}

	return nil
}

// Browse walks through all the metadata objects in subnet
func (rs subnet) Browse(task concurrency.Task, callback func(*abstract.Subnet) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "can't be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "can't be nil")
	}

	return rs.core.BrowseFolder(task, func(buf []byte) fail.Error {
		as := abstract.NewSubnet()
		if xerr := as.Deserialize(buf); xerr != nil {
			return xerr
		}
		return callback(as)
	})
}

// BindHost links host ID to the subnet
func (rs *subnet) BindHost(task concurrency.Task, host resources.Host) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	tracer := debug.NewTracer(nil, true, "("+host.GetName()+")").Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	hostID := host.GetID()
	hostName := host.GetName()

	return rs.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			subnetHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			subnetHostsV1.ByID[hostID] = hostName
			subnetHostsV1.ByName[hostName] = hostID
			return nil
		})
	})
}

// UnbindHost unlinks host ID from subnet
func (rs *subnet) UnbindHost(task concurrency.Task, hostID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.subnet"), "('"+hostID+"')").Entering()
	defer tracer.Exiting()
	// defer fail.OnExitTraceError(&xerr, tracer.TraceMessage("error occurred: "))

	return rs.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostName, found := shV1.ByID[hostID]
			if found {
				delete(shV1.ByName, hostName)
				delete(shV1.ByID, hostID)
			}
			return nil
		})
	})
}

// ListHosts returns the list of IPAddress attached to the subnet (excluding gateway)
func (rs subnet) ListHosts(task concurrency.Task) (_ []resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	defer debug.NewTracer(task, tracing.ShouldTrace("resources.subnet")).Entering().Exiting()
	// defer fail.OnExitLogError(&xerr, "error listing hosts")

	var list []resources.Host
	xerr = rs.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			svc := rs.GetService()
			for id := range shV1.ByID {
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

// InspectGateway returns the gateway related to subnet
func (rs *subnet) InspectGateway(task concurrency.Task, primary bool) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return nullHost(), fail.InvalidInstanceError()
	}
	if task == nil {
		return nullHost(), fail.InvalidParameterCannotBeNilError("task")
	}

	primaryStr := "primary"
	gwIdx := 0
	if !primary {
		primaryStr = "secondary"
		gwIdx = 1
	}
	tracer := debug.NewTracer(nil, true, "(%s)", primaryStr).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rs.cacheLock.Lock()
	defer rs.cacheLock.Unlock()

	if rs.cachedGateways[gwIdx] == nil {
		var gatewayID string
		xerr = rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			as, ok := clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if primary {
				if len(as.GatewayIDs) < 1 {
					return fail.NotFoundError("no gateway registered")
				}
				gatewayID = as.GatewayIDs[0]
			} else {
				if len(as.GatewayIDs) < 2 {
					return fail.NotFoundError("no secondary gateway registered")
				}
				gatewayID = as.GatewayIDs[1]
			}
			return nil
		})
		if xerr != nil {
			return nullHost(), xerr
		}

		if gatewayID == "" {
			return nullHost(), fail.NotFoundError("no %s gateway ID found in subnet properties", primaryStr)
		}

		rh, xerr := LoadHost(task, rs.GetService(), gatewayID)
		if xerr != nil {
			return nullHost(), xerr
		}
		rs.cachedGateways[gwIdx] = rh.(*host)
	}
	return rs.cachedGateways[gwIdx], nil
}

// GetGatewayPublicIP returns the Public IP of a particular gateway
func (rs subnet) GetGatewayPublicIP(task concurrency.Task, primary bool) (_ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task == nil {
		return "", fail.InvalidParameterCannotBeNilError("task")
	}

	var ip string
	svc := rs.GetService()
	xerr = rs.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		var (
			id  string
			rgw resources.Host
		)

		if primary {
			id = as.GatewayIDs[0]
		} else {
			if len(as.GatewayIDs) < 2 {
				return fail.InvalidRequestError("there is no secondary gateway in Subnet '%s'", rs.GetName())
			}

			id = as.GatewayIDs[1]
		}
		if rgw, innerXErr = LoadHost(task, svc, id); innerXErr != nil {
			return innerXErr
		}

		if ip, innerXErr = rgw.GetPublicIP(task); innerXErr != nil {
			return innerXErr
		}

		return nil
	})
	if xerr != nil {
		return "", xerr
	}

	return ip, nil
}

// GetGatewayPublicIPs returns a slice of public IP of gateways
func (rs subnet) GetGatewayPublicIPs(task concurrency.Task) (_ []string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var emptySlice []string
	if rs.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}
	if task == nil {
		return emptySlice, fail.InvalidParameterCannotBeNilError("task")
	}

	var gatewayIPs []string
	xerr = rs.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		gatewayIPs = make([]string, 0, len(as.GatewayIDs))
		svc := rs.GetService()
		for _, v := range as.GatewayIDs {
			rgw, innerXErr := LoadHost(task, svc, v)
			if innerXErr != nil {
				return innerXErr
			}

			ip, innerXErr := rgw.GetPublicIP(task)
			if innerXErr != nil {
				return innerXErr
			}

			gatewayIPs = append(gatewayIPs, ip)
		}
		return nil
	})
	if xerr != nil {
		return []string{}, xerr
	}

	return gatewayIPs, nil
}

// Delete deletes a Subnet
func (rs *subnet) Delete(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("operations.subnet")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	rs.SafeLock(task)
	defer rs.SafeUnlock(task)

	xerr = rs.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		svc := rs.GetService()

		// Check if hosts are still attached to subnet according to metadata
		var errorMsg string
		innerErr := props.Inspect(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostsLen := uint(len(shV1.ByName))
			if hostsLen > 0 {
				list := make([]string, 0, hostsLen)
				for k := range shV1.ByName {
					list = append(list, k)
				}
				verb := "are"
				if hostsLen == 1 {
					verb = "is"
				}
				errorMsg = fmt.Sprintf("cannot delete subnet '%s': %d host%s %s still attached to it: %s",
					as.Name, hostsLen, strprocess.Plural(hostsLen), verb, strings.Join(list, ", "))
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

		// 1st delete gateway(s)
		if innerXErr := rs.deleteGateways(task, as); innerXErr != nil {
			return innerXErr
		}

		// 2nd delete VIP if needed
		if as.VIP != nil {
			innerXErr := svc.DeleteVIP(as.VIP)
			if innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to delete VIP for gateways")
			}
		}

		// 3rd delete security groups associated to subnet by users (do not include SG created with subnet, they will be deleted later)
		innerXErr := props.Alter(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			innerXErr := rs.unbindSecurityGroups(task, ssgV1)
			return innerXErr
		})
		if innerXErr != nil {
			return innerXErr
		}

		// finally delete subnet
		logrus.Debugf("Deleting Subnet '%s'...", as.Name)
		if innerXErr = svc.DeleteSubnet(as.ID); innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// If subnet doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
				logrus.Debugf("Subnet not found on provider side, cleaning up metadata")
			default:
				return innerXErr
			}
		}
		innerXErr = retry.WhileUnsuccessfulDelay1Second(
			func() error {
				if _, recErr := svc.InspectSubnet(as.ID); recErr != nil {
					switch recErr.(type) {
					case *fail.ErrNotFound:
						// Subnet not found, good
					default:
						return recErr
					}
				}
				return nil
			},
			temporal.GetContextTimeout(),
		)
		if innerXErr != nil {
			return innerXErr
		}
		logrus.Infof("Subnet '%s' successfully deleted.", as.Name)

		// Delete Subnet's own Security Groups
		var (
			rsg    resources.SecurityGroup
			sgName string
		)
		sgs := [3]string{as.GWSecurityGroupID, as.PublicIPSecurityGroupID, as.InternalSecurityGroupID}
		for _, v := range sgs {
			if v != "" {
				if rsg, innerXErr = LoadSecurityGroup(task, svc, v); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						// Security Group not found, consider this as a success
					default:
						return innerXErr
					}
				} else {
					sgName = rsg.GetName()
					logrus.Debugf("Deleting Security Group '%s'...", sgName)
					if innerXErr = rsg.Delete(task); innerXErr != nil {
						switch innerXErr.(type) {
						case *fail.ErrNotFound:
							// Security Group not found, consider this as a success
						default:
							return innerXErr
						}
					}
				}
			}
		}

		// Remove subnet reference from owner Network
		rn, innerXErr := LoadNetwork(task, svc, as.Network)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// no Network, consider the Network metadata update as a success (this may be default Network)
			default:
				return fail.Wrap(innerXErr, "failed to query parent Network of Subnet")
			}
		} else {
			return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(task, networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
					nsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(nsV1.ByID, as.ID)
					delete(nsV1.ByName, as.Name)
					return nil
				})
			})
		}
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// Remove metadata
	return rs.core.Delete(task)
}

// InspectNetwork returns the Network instance owning the Subnet
func (rs *subnet) InspectNetwork(task concurrency.Task) (rn resources.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	rs.cacheLock.Lock()
	defer rs.cacheLock.Unlock()

	if rs.cachedNetwork == nil {
		var networkID string
		xerr = rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			as, ok := clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			networkID = as.Network
			return nil
		})
		if xerr != nil {
			return nil, xerr
		}

		rn, xerr := LoadNetwork(task, rs.GetService(), networkID)
		if xerr != nil {
			return nullNetwork(), xerr
		}

		rs.cachedNetwork = rn.(*network)
	}
	return rs.cachedNetwork, nil
}

// deleteGateways deletes all the gateways of the subnet
// A gateway host that is not found must be considered as a success
func (rs *subnet) deleteGateways(task concurrency.Task, subnet *abstract.Subnet) fail.Error {
	svc := rs.GetService()

	if len(subnet.GatewayIDs) > 0 {
		for _, v := range subnet.GatewayIDs {
			rh, xerr := LoadHost(task, svc, v)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// missing gateway is considered as a successful deletion, continue
				default:
					return xerr
				}
			} else {
				name := rh.GetName()
				logrus.Debugf("Deleting gateway '%s'...", name)
				if xerr := rh.(*host).relaxedDeleteHost(task); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// missing gateway is considered as a successful deletion, continue
					default:
						return xerr
					}
				}
				logrus.Debugf("Gateway '%s' successfully deleted.", name)
			}

			// Remove current entry from gateways to delete
			subnet.GatewayIDs = subnet.GatewayIDs[1:]
		}
	}
	return nil
}

// unbindSecurityGroups makes sure the security groups bound to subnet are unbound
func (rs *subnet) unbindSecurityGroups(task concurrency.Task, sgs *propertiesv1.SubnetSecurityGroups) (xerr fail.Error) {
	var rsg resources.SecurityGroup
	svc := rs.GetService()
	for k, v := range sgs.ByName {
		if rsg, xerr = LoadSecurityGroup(task, svc, v); xerr == nil {
			xerr = rsg.UnbindFromSubnet(task, rs)
		}
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// consider a Security Group not found as a successful unbind
			default:
				return xerr
			}
		} else if xerr = rsg.Delete(task); xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Consider a Security Group not found as a successful deletion and continue
			default:
				return xerr
			}
		}
		delete(sgs.ByID, v)
		delete(sgs.ByName, k)
	}
	return nil
}

// GetDefaultRouteIP returns the IP of the LAN default route
func (rs subnet) GetDefaultRouteIP(task concurrency.Task) (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task == nil {
		return "", fail.InvalidParameterCannotBeNilError("task")
	}

	ip = ""
	xerr = rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if as.VIP != nil && as.VIP.PrivateIP != "" {
			ip = as.VIP.PrivateIP
			return nil
		}
		if len(as.GatewayIDs) > 0 {
			rh, innerErr := LoadHost(task, rs.GetService(), as.GatewayIDs[0])
			if innerErr != nil {
				return innerErr
			}

			ip = rh.(*host).getPrivateIP(task)
			return nil
		}

		return fail.NotFoundError("failed to find default route IP: no gateway defined")
	})
	return ip, xerr
}

// getDefaultRouteIP ...
func (rs subnet) getDefaultRouteIP(task concurrency.Task) string {
	if rs.IsNull() {
		return ""
	}
	ip, _ := rs.GetDefaultRouteIP(task)
	return ip
}

// GetEndpointIP returns the internet (public) IP to reach the subnet
func (rs subnet) GetEndpointIP(task concurrency.Task) (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	ip = ""
	if rs.IsNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task == nil {
		return ip, fail.InvalidParameterCannotBeNilError("task")
	}

	xerr = rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if as.VIP != nil && as.VIP.PublicIP != "" {
			ip = as.VIP.PublicIP
		} else {
			objpgw, inErr := LoadHost(task, rs.GetService(), as.GatewayIDs[0])
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

// HasVirtualIP tells if the subnet uses a VIP a default route
func (rs subnet) HasVirtualIP(task concurrency.Task) bool {
	if rs.IsNull() {
		logrus.Errorf(fail.InvalidInstanceError().Error())
		return false
	}
	if task == nil {
		logrus.Errorf(fail.InvalidParameterCannotBeNilError("task").Error())
		return false
	}

	var found bool
	xerr := rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		found = as.VIP != nil
		return nil
	})
	return xerr == nil && found
}

// GetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (rs subnet) GetVirtualIP(task concurrency.Task) (vip *abstract.VirtualIP, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	xerr = rs.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		vip = as.VIP
		return nil
	})
	if xerr != nil {
		return nil, fail.Wrap(xerr, "cannot get subnet virtual IP")

	}
	if vip == nil {
		return nil, fail.NotFoundError("failed to find Virtual IP binded to gateways for subnet '%s'", rs.GetName())
	}
	return vip, nil
}

// GetCIDR returns the CIDR of the subnet
func (rs subnet) GetCIDR(task concurrency.Task) (cidr string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task == nil {
		return "", fail.InvalidParameterCannotBeNilError("task")
	}

	cidr = ""
	xerr = rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		cidr = as.CIDR
		return nil
	})
	return cidr, xerr
}

// getCIDR returns the CIDR of the network
// Intended to be used when objn is notoriously not nil (because previously checked)
func (rs subnet) getCIDR(task concurrency.Task) string {
	cidr, _ := rs.GetCIDR(task)
	return cidr
}

// GetState returns the current state of the subnet
func (rs subnet) GetState(task concurrency.Task) (state subnetstate.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return subnetstate.UNKNOWN, fail.InvalidInstanceError()
	}
	if task == nil {
		return subnetstate.UNKNOWN, fail.InvalidParameterCannotBeNilError("task")
	}

	xerr = rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		state = as.State
		return nil
	})
	return state, xerr
}

// getState returns the state of the network
// Intended to be used when rs is notoriously not null (because previously checked)
func (rs subnet) getState(task concurrency.Task) subnetstate.Enum {
	state, _ := rs.GetState(task)
	return state
}

// ToProtocol converts resources.Network to protocol.Network
func (rs subnet) ToProtocol(task concurrency.Task) (_ *protocol.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"), "").Entering()
	defer tracer.Exiting()

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to convert resources.Subnet to *protocol.Subnet")
		}
	}()

	var (
		gw  resources.Host
		vip *abstract.VirtualIP
	)

	// Get primary gateway ID
	gw, xerr = rs.InspectGateway(task, true)
	if xerr != nil {
		return nil, xerr
	}
	primaryGatewayID := gw.GetID()

	// Get secondary gateway id if such a gateway exists
	gwIDs := []string{primaryGatewayID}
	gw, xerr = rs.InspectGateway(task, false)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return nil, xerr
		}
	} else {
		gwIDs = append(gwIDs, gw.GetID())
	}

	pn := &protocol.Subnet{
		Id:         rs.GetID(),
		Name:       rs.GetName(),
		Cidr:       rs.getCIDR(task),
		GatewayIds: gwIDs,
		Failover:   rs.HasVirtualIP(task),
		State:      protocol.SubnetState(rs.getState(task)),
	}

	vip, xerr = rs.GetVirtualIP(task)
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

// BindSecurityGroup binds a security group to the subnet; if enabled is true, apply it immediately
func (rs *subnet) BindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup, enabled resources.SecurityGroupActivation) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if sg == nil {
		return fail.InvalidParameterCannotBeNilError("sg")
	}

	return rs.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// First check if the security group is not already registered for the host with the exact same state
			for k, v := range nsgV1.ByID {
				if k == sgID && v.Disabled == bool(!enabled) {
					return fail.DuplicateError("security group '%s' already bound to subnet")
				}
			}

			// Bind the security group to the subnet (does the security group side of things)
			if innerXErr := sg.BindToSubnet(task, rs, enabled, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
				return innerXErr
			}

			// Updates subnet metadata
			nsgV1.ByID[sgID].Disabled = bool(!enabled)
			return nil
		})
	})
}

// UnbindSecurityGroup unbinds a security group from the host
func (rs *subnet) UnbindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if sg == nil {
		return fail.InvalidParameterCannotBeNilError("sg")
	}

	return rs.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// Check if the security group is listed for the host, inot already registered for the host with the exact same state
			found := false
			for k := range ssgV1.ByID {
				if k == sgID {
					found = true
					break
				}
			}
			// If not found, consider request successful
			if !found {
				return nil
			}

			// unbind security group from subnet on cloud provider side
			if innerXErr := sg.UnbindFromSubnet(task, rs); innerXErr != nil {
				return innerXErr
			}

			// updates the metadata
			delete(ssgV1.ByID, sgID)
			delete(ssgV1.ByName, sg.GetName())
			return nil

		})
	})
}

// ListSecurityGroups returns a slice of security groups bound to subnet
func (rs *subnet) ListSecurityGroups(task concurrency.Task, state securitygroupstate.Enum) (list []*propertiesv1.SecurityGroupBond, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var nullList []*propertiesv1.SecurityGroupBond
	if rs.IsNull() {
		return nullList, fail.InvalidInstanceError()
	}
	if task == nil {
		return nullList, fail.InvalidParameterError("task", "cannot be null value of '*concurrency.Task'")
	}

	return list, rs.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = filterBondsByKind(ssgV1.ByID, state)
			return nil
		})
	})
}

// EnableSecurityGroup enables a binded security group to subnet
func (rs *subnet) EnableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if sg == nil {
		return fail.InvalidParameterCannotBeNilError("sg")
	}

	svc := rs.GetService()
	return rs.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var asg *abstract.SecurityGroup
			xerr := sg.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				var ok bool
				if asg, ok = clonable.(*abstract.SecurityGroup); !ok {
					return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			if xerr != nil {
				return xerr
			}

			// First check if the security group is not already registered for the host with the exact same state
			var found bool
			for k := range nsgV1.ByID {
				if k == asg.ID {
					found = true
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not binded to subnet '%s'", sg.GetName(), rs.GetID())
			}

			// Do security group stuff to enable it
			if svc.GetCapabilities().CanDisableSecurityGroup {
				if xerr = svc.EnableSecurityGroup(asg); xerr != nil {
					return xerr
				}
			} else {
				if xerr = sg.BindToSubnet(task, rs, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrDuplicate:
						// security group already bound to subnet with the same state, consider as a success
					default:
						return xerr
					}
				}
			}

			// update metadata
			nsgV1.ByID[asg.ID].Disabled = false
			return nil
		})
	})
}

// DisableSecurityGroup disables an already binded security group on subnet
func (rs *subnet) DisableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if sg == nil {
		return fail.InvalidParameterCannotBeNilError("sg")
	}

	svc := rs.GetService()
	return rs.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var asg *abstract.SecurityGroup
			xerr := sg.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				var ok bool
				if asg, ok = clonable.(*abstract.SecurityGroup); !ok {
					return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			if xerr != nil {
				return xerr
			}

			// First check if the security group is not already registered for the host with the exact same state
			if _, ok := nsgV1.ByID[asg.ID]; !ok {
				return fail.NotFoundError("security group '%s' is not bound to subnet '%s'", sg.GetName(), rs.GetID())
			}

			if svc.GetCapabilities().CanDisableSecurityGroup {
				if xerr = svc.DisableSecurityGroup(asg); xerr != nil {
					return xerr
				}
			} else {
				// Do security group stuff to disable it
				if xerr = sg.BindToSubnet(task, rs, resources.SecurityGroupDisable, resources.KeepCurrentSecurityGroupMark); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// security group not bound to subnet, consider as a success
					default:
						return xerr
					}
				}
			}

			// update metadata
			nsgV1.ByID[asg.ID].Disabled = true
			return nil
		})
	})
}

// InspectGatewaySecurityGroup returns the instance of SecurityGroup in Subnet related to external access on gateways
func (rs subnet) InspectGatewaySecurityGroup(task concurrency.Task) (sg resources.SecurityGroup, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	sg = nullSecurityGroup()
	if rs.IsNull() {
		return sg, fail.InvalidInstanceError()
	}
	if task == nil {
		return sg, fail.InvalidParameterCannotBeNilError("task")
	}

	xerr = rs.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		sg, innerXErr = LoadSecurityGroup(task, rs.GetService(), as.GWSecurityGroupID)
		return innerXErr
	})
	return sg, xerr
}

// InspectInternalSecurityGroup returns the instance of SecurityGroup for internal security inside the Subnet
func (rs subnet) InspectInternalSecurityGroup(task concurrency.Task) (sg resources.SecurityGroup, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	sg = nullSecurityGroup()
	if rs.IsNull() {
		return sg, fail.InvalidInstanceError()
	}
	if task == nil {
		return sg, fail.InvalidParameterCannotBeNilError("task")
	}

	xerr = rs.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		sg, innerXErr = LoadSecurityGroup(task, rs.GetService(), as.InternalSecurityGroupID)
		return innerXErr
	})
	return sg, xerr
}

// InspectPublicIPSecurityGroup returns the instance of SecurityGroup in Subnet for Hosts with Public IP (which does not apply on gateways)
func (rs subnet) InspectPublicIPSecurityGroup(task concurrency.Task) (sg resources.SecurityGroup, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	sg = nullSecurityGroup()
	if rs.IsNull() {
		return sg, fail.InvalidInstanceError()
	}
	if task == nil {
		return sg, fail.InvalidParameterCannotBeNilError("task")
	}

	xerr = rs.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		sg, innerXErr = LoadSecurityGroup(task, rs.GetService(), as.PublicIPSecurityGroupID)
		return innerXErr
	})
	return sg, xerr
}

// // InspectNetwork returns the resources.Network instance of parent Network of the Subnet
// func (rs *subnet) InspectNetwork(task concurrency.Task) (_ resources.Network, xerr fail.Error) {
// 	defer fail.OnPanic(&xerr)
//
// 	if rs.IsNull() {
// 		return nil, fail.InvalidInstanceError()
// 	}
//
// 	var networkID string
// 	xerr := rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
// 		as, ok := clonable.(*abstract.Subnet)
// 		if !ok {
// 			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
// 		}
// 		networkID = as.Network
// 		return nil
// 	})
// 	if xerr != nil {
// 		return nil, xerr
// 	}
// 	if networkID == "" {
// 		return nil, fail.InconsistentError("metadata of Subnet does not reference a parent Network")
// 	}
//
// 	return LoadNetwork(task, rs.GetService(), networkID)
// }
