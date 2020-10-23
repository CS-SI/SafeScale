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

package operations

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
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
	"github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// networksFolderName is the technical name of the container used to store networks info
	subnetsFolderName = "subnets"

	subnetInternalSecurityGroupNamePattern        = "subnet_%s_internal_sg"
	subnetInternalSecurityGroupDescriptionPattern = "Subnet '%s' Security Group for internal access"
	subnetGWSecurityGroupNamePattern              = "subnet_%s_gateway_sg"
	subnetGWSecurityGroupDescriptionPattern       = "Subnet '%s' Security Group for gateway"
	subnetPublicSecurityGroupNamePattern          = "subnet_%s_public_sg"
	subnetPublicSecurityGroupDescriptionPattern   = "Subnet '%s' Security Group for hosts with public IP (excluding gateways)"
)

// subnet links Object Storage folder and Subnet
type subnet struct {
	*core
}

func nullSubnet() *subnet {
	return &subnet{core: nullCore()}
}

// NewSubnet creates an instance of subnet used as resources.Subnet
func NewSubnet(svc iaas.Service) (resources.Subnet, fail.Error) {
	if svc.IsNull() {
		return nullSubnet(), fail.InvalidParameterError("svc", "cannot be null value")
	}

	coreInstance, xerr := newCore(svc, "subnet", subnetsFolderName, &abstract.Subnet{})
	if xerr != nil {
		return nullSubnet(), xerr
	}

	return &subnet{core: coreInstance}, nil
}

// lookupSubnet tells if a Subnet exists
func lookupSubnet(task concurrency.Task, svc iaas.Service, networkRef, subnetRef string) (_ bool, xerr fail.Error) {
	if task.IsNull() {
		return false, fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc.IsNull() {
		return false, fail.InvalidParameterError("svc", "cannot be null value")
	}
	if subnetRef == "" {
		return false, fail.InvalidParameterError("subnetRef", "cannot be empty string")
	}

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
	if task.IsNull() {
		return nullSubnet(), fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc.IsNull() {
		return nullSubnet(), fail.InvalidParameterError("svc", "cannot be null value")
	}
	if subnetRef == "" {
		return nullSubnet(), fail.InvalidParameterError("subnetRef", "cannot be empty string")
	}

	rs = nil
	var subnetID string
	if networkRef != "" {
		// If networkRef is not empty, make sure the subnetRef is inside the network
		rn, xerr := LoadNetwork(task, svc, networkRef)
		if xerr != nil {
			return nil, xerr
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
					return fail.NotFoundError("failed to find a subnet referenced by '%s' in network '%s'", subnetRef, rn.GetName())
				}
				return nil
			})
		})
		if xerr != nil {
			return nil, xerr
		}
	} else {
		// If networkRef is empty, subnetRef must be subnetID
		subnetID = subnetRef
	}

	rs, xerr = NewSubnet(svc)
	if xerr != nil {
		return nullSubnet(), xerr
	}
	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return rs.ReadByID(task, subnetID)
		},
		10*time.Second, // FIXME: parameterize
	)
	if xerr != nil {
		return nullSubnet(), xerr
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
	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(
		task,
		tracing.ShouldTrace("resources.subnet"),
		"('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.Image, req.HA,
	).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr)
	defer fail.OnPanic(&xerr)

	// Check if subnet already exists and is managed by SafeScale
	svc := rs.GetService()
	if found, xerr := lookupSubnet(task, svc, req.Network, req.Name); xerr == nil && found {
		return fail.DuplicateError("subnet '%s' already exists", req.Name)
	}

	// Verify if the subnet already exist and in this case is not managed by SafeScale
	if _, xerr = svc.InspectSubnetByName(req.Network, req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		case *fail.ErrInvalidRequest, *fail.ErrTimeout:
			return xerr
		default:
			return xerr
		}
	} else {
		return fail.DuplicateError("subnet '%s' already exists (not managed by SafeScale)", req.Name)
	}

	// Verify the IPRanges is not routable
	if req.CIDR != "" {
		routable, xerr := net.IsCIDRRoutable(req.CIDR)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to determine if IPRanges is not routable")
		}
		if routable {
			return fail.InvalidRequestError("cannot create such a subnet, IPRanges must not be routable; please choose as appropriate IPRanges (RFC1918)")
		}
	}

	// Verify the network exists and make sure req.Network field is an ID
	rn, xerr := LoadNetwork(task, svc, req.Network)
	if xerr != nil {
		return xerr
	}
	req.Network = rn.GetID()

	// Creates security group for gateway(s) of Subnet
	//sgName := fmt.Sprintf(subnetGWSecurityGroupNamePattern, req.Name)
	//rules := stacks.DefaultTCPRules()
	//rules = append(rules, stacks.DefaultUDPRules()...)
	//rules = append(rules, stacks.DefaultICMPRules()...)
	//subnetGWSG, xerr := NewSecurityGroup(svc)
	//if xerr != nil {
	//	return xerr
	//}
	//xerr = subnetGWSG.Create(task, rn, sgName, fmt.Sprintf(subnetGWSecurityGroupDescriptionPattern, req.Name), rules)
	//if xerr != nil {
	//	return xerr
	//}
	//
	//// Starting from here, delete the security group in exiting with error
	//defer func() {
	//	if xerr != nil && !req.KeepOnFailure {
	//		if derr := subnetGWSG.Delete(task); derr != nil {
	//			_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove Security Group for gateways '%s'", sgName))
	//		}
	//	}
	//}()

	var (
		cancel                       func(*fail.Error)
		subnetGWSG, subnetInternalSG resources.SecurityGroup
	)
	if subnetGWSG, cancel, xerr = rs.createGWSecurityGroup(task, req, rn); xerr != nil {
		return xerr
	}
	defer cancel(&xerr)

	// Creates security group for hosts in Subnet to allow internal access
	//sgName = fmt.Sprintf(subnetInternalSecurityGroupNamePattern, req.Name)
	//rules = stacks.DefaultTCPRules()
	//rules = append(rules, stacks.DefaultUDPRules()...)
	//rules = append(rules, stacks.DefaultICMPRules()...)
	//subnetInternalSG, xerr := NewSecurityGroup(svc)
	//if xerr != nil {
	//	return xerr
	//}
	//if xerr = subnetInternalSG.Create(task, rn, sgName, fmt.Sprintf(subnetInternalSecurityGroupDescriptionPattern, req.Name), rules); xerr != nil {
	//	return xerr
	//}
	//
	//// Starting from here, delete the Security Group if exiting with error
	//defer func() {
	//	if xerr != nil && !req.KeepOnFailure {
	//		if derr := subnetInternalSG.Delete(task); derr != nil {
	//			_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove Security Group for public Hosts '%s'", sgName))
	//		}
	//	}
	//}()

	if subnetInternalSG, cancel, xerr = rs.createInternalSecurityGroup(task, req, rn); xerr != nil {
		return xerr
	}
	defer cancel(&xerr)

	// Create the subnet
	logrus.Debugf("Creating subnet '%s' with CIDR '%s'...", req.Name, req.CIDR)
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
			if derr := svc.DeleteSubnet(as.ID); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete subnet"))
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
			if derr := rs.core.Delete(task); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete subnet metadata"))
			}
		}
	}()

	xerr = subnetGWSG.BindToSubnet(task, rs, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := subnetGWSG.UnbindFromSubnet(task, rs); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind Security Group for gateway from subnet"))
			}
		}
	}()

	xerr = subnetInternalSG.BindToSubnet(task, rs, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsDefault)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := subnetInternalSG.UnbindFromSubnet(task, rs); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind Security Group for Hosts from Subnet"))
			}
		}
	}()

	caps := svc.GetCapabilities()
	failover := req.HA
	if failover {
		if caps.PrivateVirtualIP {
			logrus.Info("Provider support private Virtual IP, honoring the failover setup for gateways.")
		} else {
			logrus.Warning("Provider does not support private Virtual IP, cannot set up failover of subnet default route.")
			failover = false
		}
	}

	// Creates VIP for gateways if asked for
	if failover {
		if as.VIP, xerr = svc.CreateVIP(as.ID, as.Network, fmt.Sprintf("for gateways of subnet %s", as.Name), []string{subnetGWSG.GetID()}); xerr != nil {
			return fail.Wrap(xerr, "failed to create VIP")
		}

		// Starting from here, delete VIP if exists with error
		defer func() {
			if xerr != nil && as != nil && as.VIP != nil && !req.KeepOnFailure {
				if derr := svc.DeleteVIP(as.VIP); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete VIP"))
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

	// attach subnet to network
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
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to detach Subnet from Network"))
			}
		}
	}()

	var template *abstract.HostTemplate
	if gwSizing == nil {
		gwSizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}
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
		return fail.NotFoundError("error creating subnet: no host template matching requirements for gateway")
	}

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

	keypairName := "kp_" + subnetName
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
		Subnets:       []*abstract.Subnet{as},
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
	primaryTask, xerr = task.StartInSubtask(rs.taskCreateGateway, data.Map{
		"request": primaryRequest,
		"sizing":  *gwSizing,
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
		secondaryTask, xerr = task.StartInSubtask(rs.taskCreateGateway, data.Map{
			"request": secondaryRequest,
			"sizing":  *gwSizing,
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
						_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind VIP from gateway"))
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
					if derr := secondaryGateway.relaxedDeleteHost(task); xerr != nil {
						switch derr.(type) {
						case *fail.ErrTimeout:
							logrus.Warnf("We should have waited more") // FIXME: Wait until gateway no longer exists
						default:
						}
						_ = xerr.AddConsequence(derr)
					}
					if derr := rs.unbindHostFromVIP(as.VIP, secondaryGateway); derr != nil {
						_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind VIP from gateway"))
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

	// Update metadata of subnet object
	xerr = rs.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// as.GatewayID = primaryGateway.GetID()
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

	// Binds subnet default security group to gateway(s)
	//xerr = primaryGateway.BindSecurityGroup(task, subnetGWSG, resources.SecurityGroupEnable)
	//if xerr != nil {
	//	return xerr
	//}
	//if failover {
	//	xerr = secondaryGateway.BindSecurityGroup(task, subnetGWSG, resources.SecurityGroupEnable)
	//	if xerr != nil {
	//		return xerr
	//	}
	//}

	// As hosts are gateways, the configuration stopped on phase 2 'netsec', the remaining 3 phases have to be run explicitly
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

	primaryTask, xerr = primaryTask.Start(rs.taskFinalizeGatewayConfiguration, data.Map{
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
		secondaryTask, xerr = secondaryTask.Start(rs.taskFinalizeGatewayConfiguration, data.Map{
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

	// Updates subnet state in metadata
	// logrus.Debugf("Updating subnet metadata '%s' ...", subnet.GetName)
	return rs.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		as.State = subnetstate.READY
		return nil
	})
}

func (rs subnet) createGWSecurityGroup(task concurrency.Task, req abstract.SubnetRequest, rn resources.Network) (resources.SecurityGroup, func(*fail.Error), fail.Error) {
	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetGWSecurityGroupNamePattern, req.Name)
	rules := abstract.SecurityGroupRules{
		{
			Description: "[ingress][ipv4][tcp] Allow SSH",
			Direction:   securitygroupruledirection.INGRESS,
			PortFrom:    22,
			//PortTo:      22,
			EtherType: ipversion.IPv4,
			Protocol:  "tcp",
			IPRanges:  []string{"0.0.0.0/0"},
		},
		{
			Description: "[ingress][ipv6][tcp] Allow SSH",
			Direction:   securitygroupruledirection.INGRESS,
			PortFrom:    22,
			//PortTo:      22,
			EtherType: ipversion.IPv6,
			Protocol:  "tcp",
			IPRanges:  []string{"::/0"},
		},
		{
			Description: "[ingress][ipv4][icmp] Allow everything",
			Direction:   securitygroupruledirection.INGRESS,
			EtherType:   ipversion.IPv4,
			Protocol:    "icmp",
			IPRanges:    []string{"0.0.0.0/0"},
		},
		{
			Description: "[ingress][ipv6][icmp] Allow everything",
			Direction:   securitygroupruledirection.INGRESS,
			EtherType:   ipversion.IPv6,
			Protocol:    "icmp",
			IPRanges:    []string{"::/0"},
		},
	}

	var (
		xerr fail.Error
		sg   resources.SecurityGroup
	)
	if sg, xerr = NewSecurityGroup(rs.GetService()); xerr == nil {
		description := fmt.Sprintf(subnetGWSecurityGroupDescriptionPattern, req.Name)
		xerr = sg.Create(task, rn, sgName, description, rules)
	}
	if xerr != nil {
		return nil, nil, xerr
	}

	// Starting from here, delete the Security Group if exiting with error
	cancelFunc := func(errorPtr *fail.Error) {
		if errorPtr == nil {
			logrus.Errorf("trying to cancel an action based on the content of a nil fail.Error; cancel cannot be run")
			return
		}
		if *errorPtr != nil && !req.KeepOnFailure {
			if derr := sg.Delete(task); derr != nil {
				_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove Subnet's Security Group for gateways '%s'", sgName))
			}
		}
	}

	return sg, cancelFunc, nil
}

// Creates security group for hosts in Subnet to allow internal access
func (rs subnet) createInternalSecurityGroup(task concurrency.Task, req abstract.SubnetRequest, rn resources.Network) (resources.SecurityGroup, func(*fail.Error), fail.Error) {
	sgName := fmt.Sprintf(subnetInternalSecurityGroupNamePattern, req.Name)
	rules := abstract.SecurityGroupRules{
		{
			Description: "[ingress][ipv4][tcp] Allow LAN traffic",
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.INGRESS,
			Protocol:    "tcp",
			IPRanges:    []string{req.CIDR},
		},
		{
			Description: "[ingress][ipv4][udp] Allow LAN traffic",
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.INGRESS,
			Protocol:    "udp",
			IPRanges:    []string{req.CIDR},
		},
		{
			Description: "[egress][ipv4][tcp] Allow anything",
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.EGRESS,
			Protocol:    "tcp",
			IPRanges:    []string{"0.0.0.0/0"},
		},
		{
			Description: "[egress][IPv4] Allow anything",
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.EGRESS,
			Protocol:    "udp",
			IPRanges:    []string{"0.0.0.0/0"},
		},
		{
			Description: "[egress][ipv6][tcp] allow anything",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.EGRESS,
			Protocol:    "tcp",
			IPRanges:    []string{"::/0"},
		},
		{
			Description: "[egress][ipv6][udp] Allow anything",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.EGRESS,
			Protocol:    "udp",
			IPRanges:    []string{"::/0"},
		},
		{
			Description: "[egress][ipv4][icmp] Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			EtherType:   ipversion.IPv4,
			Protocol:    "icmp",
			IPRanges:    []string{"0.0.0.0/0"},
		},
		{
			Description: "[egress][ipv6][icmp] Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			EtherType:   ipversion.IPv6,
			Protocol:    "icmp",
			IPRanges:    []string{"::/0"},
		},
	}
	var (
		xerr fail.Error
		sg   resources.SecurityGroup
	)
	if sg, xerr = NewSecurityGroup(rs.GetService()); xerr == nil {
		description := fmt.Sprintf(subnetInternalSecurityGroupDescriptionPattern, req.Name)
		xerr = sg.Create(task, rn, sgName, description, rules)
	}
	if xerr != nil {
		return nil, nil, xerr
	}

	// Starting from here, delete the Security Group if exiting with error
	cancelFunc := func(errorPtr *fail.Error) {
		if errorPtr == nil {
			logrus.Errorf("trying to cancel an action based on the content of a nil fail.Error; cancel cannot be run")
			return
		}
		if *errorPtr != nil && !req.KeepOnFailure {
			if derr := sg.Delete(task); derr != nil {
				_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove Subnet's Security Group for internal access '%s'", sgName))
			}
		}
	}

	return sg, cancelFunc, nil
}

func (rs subnet) unbindHostFromVIP(vip *abstract.VirtualIP, host resources.Host) fail.Error {
	if xerr := rs.GetService().UnbindHostFromVIP(vip, host.GetID()); xerr != nil {
		return fail.Wrap(xerr, "cleaning up on failure, failed to unbind gateway '%s' from VIP", host.GetName())
	}
	//logrus.Infof("Cleaning up on failure, host '%s' bind removed from VIP", name)
	return nil
}

//// Delete deletes subnet
//func (rs *subnet) Delete(task concurrency.Task) (xerr fail.Error) {
//	if rs.IsNull() {
//		return fail.InvalidInstanceError()
//	}
//	if task.IsNull() {
//		return fail.InvalidParameterError("task", "cannot be nil")
//	}
//
//	tracer := debug.NewTracer(nil, true, "").WithStopwatch().Entering()
//	defer tracer.Exiting()
//	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
//	defer fail.OnPanic(&xerr)
//
//	rs.SafeLock(task)
//	defer rs.SafeUnlock(task)
//
//
//	// Then delete subnet
//	xerr = rs.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
//		as, ok := clonable.(*abstract.Subnet)
//		if !ok {
//			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
//		}
//
//		svc := rs.GetService()
//
//		waitMore := false
//		// delete subnet, with tolerance
//		innerErr := svc.DeleteSubnet(as.ID)
//		if innerErr != nil {
//			switch innerErr.(type) {
//			case *fail.ErrNotFound:
//				// If subnet doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
//				logrus.Warnf("subnet not found on provider side, cleaning up metadata.")
//				return innerErr
//			case *fail.ErrTimeout:
//				logrus.Error("cannot delete subnet due to a timeout")
//				waitMore = true
//			default:
//				logrus.Error("cannot delete subnet, other reason")
//			}
//		}
//		if waitMore {
//			errWaitMore := retry.WhileUnsuccessfulDelay1Second(
//				func() error {
//					recNet, recErr := svc.InspectSubnet(as.ID)
//					if recNet != nil {
//						return fmt.Errorf("still there")
//					}
//					if _, ok := recErr.(*fail.ErrNotFound); ok {
//						return nil
//					}
//					return fail.Wrap(recErr, "another kind of error")
//				},
//				temporal.GetContextTimeout(),
//			)
//			if errWaitMore != nil {
//				_ = innerErr.AddConsequence(errWaitMore)
//			}
//		}
//		return innerErr
//	})
//	if xerr != nil {
//		return xerr
//	}
//
//	// Remove metadata
//	return rs.core.Delete(task)
//}

// Browse walks through all the metadata objects in subnet
func (rs subnet) Browse(task concurrency.Task, callback func(*abstract.Subnet) fail.Error) fail.Error {
	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
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
	if rs.IsNull() {
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

	return rs.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			networkHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			networkHostsV1.ByID[hostID] = hostName
			networkHostsV1.ByName[hostName] = hostID
			return nil
		})
	})
}

// UnbindHost unlinks host ID from subnet
func (rs *subnet) UnbindHost(task concurrency.Task, hostID string) (xerr fail.Error) {
	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.subnet"), "('"+hostID+"')").Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

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

// ListHosts returns the list of Host attached to the subnet (excluding gateway)
func (rs subnet) ListHosts(task concurrency.Task) (_ []resources.Host, xerr fail.Error) {
	if rs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	defer debug.NewTracer(task, tracing.ShouldTrace("resources.subnet")).Entering().Exiting()
	defer fail.OnExitLogError(&xerr, "error listing hosts")
	defer fail.OnPanic(&xerr)

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

// GetGateway returns the gateway related to subnet
func (rs subnet) GetGateway(task concurrency.Task, primary bool) (_ resources.Host, xerr fail.Error) {
	if rs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
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
	xerr = rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
		return nil, xerr
	}
	if gatewayID == "" {
		return nil, fail.NotFoundError("no %s gateway ID found in subnet properties", primaryStr)
	}
	return LoadHost(task, rs.GetService(), gatewayID)
}

//// getGateway returns a resources.Host corresponding to the gateway requested. May return HostNull if no gateway exists.
//func (rs subnet) getGateway(task concurrency.Task, primary bool) resources.Host {
//	host, _ := rs.GetGateway(task, primary)
//	return host
//}

// Delete deletes a Subnet
func (rs *subnet) Delete(task concurrency.Task) (xerr fail.Error) {
	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	rs.SafeLock(task)
	defer rs.SafeUnlock(task)

	// var gwID string
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

		// 3rd delete security groups associated to subnet
		innerXErr := props.Alter(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return rs.unbindSecurityGroups(task, ssgV1)
		})
		if innerXErr != nil {
			return innerXErr
		}

		// finally delete subnet
		logrus.Debugf("Deleting Subnet '%s'...", as.Name)
		waitMore := false
		innerXErr = svc.DeleteSubnet(as.ID)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// If subnet doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
				logrus.Warnf("Subnet not found on provider side, cleaning up metadata.")
				return innerXErr
			case *fail.ErrTimeout:
				logrus.Error("Cannot delete subnet due to a timeout")
				waitMore = true
			default:
				logrus.Error("Cannot delete subnet, other reason: %s", innerXErr.Error())
			}
		}
		if waitMore {
			xerrWaitMore := retry.WhileUnsuccessfulDelay1Second(
				func() error {
					recNet, recErr := svc.InspectSubnet(as.ID)
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
			if xerrWaitMore != nil {
				if innerXErr == nil {
					innerXErr = xerrWaitMore
				} else {
					_ = innerXErr.AddConsequence(xerrWaitMore)
				}
			}
		}
		logrus.Debugf("Subnet '%s' successfully deleted.", as.Name)

		// Delete Subnet's own Security Groups
		if as.GWSecurityGroupID != "" {
			rsg, innerXErr := LoadSecurityGroup(task, svc, as.GWSecurityGroupID)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// Security Group not found, consider this as a success
				default:
					return innerXErr
				}
			} else {
				sgName := rsg.GetName()
				logrus.Debugf("Deleting Security Group %s...", sgName)
				if innerXErr = rsg.Delete(task); innerXErr != nil {
					return innerXErr
				}
				logrus.Debugf("Security Group %s successfully deleted.", sgName)
			}
		}
		if as.InternalSecurityGroupID != "" {
			rsg, innerXErr := LoadSecurityGroup(task, svc, as.InternalSecurityGroupID)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// Security group not found, consider this as a success
				default:
					return innerXErr
				}
			} else {
				sgName := rsg.GetName()
				logrus.Debugf("Deleting Security Group %s...", sgName)
				if innerXErr = rsg.Delete(task); innerXErr != nil {
					return innerXErr
				}
				logrus.Debugf("Security Group %s successfully deleted.", sgName)
			}
		}
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// Remove metadata
	return rs.core.Delete(task)
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
					logrus.Infof("Gateway '%s' of Subnet '%s' appears to be already deleted", v, subnet.Name)
				default:
					return xerr
				}
			} else {
				logrus.Debugf("Deleting gateway '%s'...", rh.GetName())
				if xerr := rh.(*host).relaxedDeleteHost(task); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						logrus.Infof("Gateway seems already deleted")
					default:
						return xerr
					}
				}
				logrus.Debugf("Gateway '%s' successfully deleted.", rh.GetName())
			}

			// Remove current entry from gateways to delete
			subnet.GatewayIDs = subnet.GatewayIDs[1:]
		}
	}
	return nil
}

// unbindSecurityGroups makes sure the security groups bound to subnet are unbound
func (rs *subnet) unbindSecurityGroups(task concurrency.Task, sgs *propertiesv1.SubnetSecurityGroups) fail.Error {
	svc := rs.GetService()
	for k, v := range sgs.ByName {
		rsg, innerXErr := LoadSecurityGroup(task, svc, v)
		if innerXErr != nil {
			return innerXErr
		}

		if innerXErr = rsg.UnbindFromSubnet(task, rs); innerXErr != nil {
			return innerXErr
		}

		delete(sgs.ByID, v)
		delete(sgs.ByName, k)
	}
	return nil
}

// GetDefaultRouteIP returns the IP of the LAN default route
func (rs subnet) GetDefaultRouteIP(task concurrency.Task) (ip string, xerr fail.Error) {
	if rs.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return "", fail.InvalidParameterError("task", "cannot be nil")
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

// GetEndpointIP returns the IP of the internet IP to reach the subnet
func (rs subnet) GetEndpointIP(task concurrency.Task) (ip string, xerr fail.Error) {
	ip = ""
	if rs.IsNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return ip, fail.InvalidParameterError("task", "cannot be nil")
	}

	xerr = rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
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

// getEndpointIP ...
func (rs subnet) getEndpointIP(task concurrency.Task) string {
	if rs.IsNull() {
		return ""
	}
	ip, _ := rs.GetEndpointIP(task)
	return ip
}

// HasVirtualIP tells if the subnet uses a VIP a default route
func (rs subnet) HasVirtualIP(task concurrency.Task) bool {
	if rs.IsNull() {
		logrus.Errorf(fail.InvalidInstanceError().Error())
		return false
	}

	var found bool
	xerr := rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		found = as.VIP != nil
		return nil
	})
	return xerr == nil && found
}

// GetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (rs subnet) GetVirtualIP(task concurrency.Task) (vip *abstract.VirtualIP, xerr fail.Error) {
	if rs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
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

// GetCIDR returns the IPRanges of the subnet
func (rs subnet) GetCIDR(task concurrency.Task) (cidr string, xerr fail.Error) {
	if rs.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return "", fail.InvalidParameterError("task", "cannot be nil")
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

// getCIDR returns the IPRanges of the network
// Intended to be used when objn is notoriously not nil (because previously checked)
func (rs subnet) getCIDR(task concurrency.Task) string {
	cidr, _ := rs.GetCIDR(task)
	return cidr
}

// GetState returns the current state of the subnet
func (rs subnet) GetState(task concurrency.Task) (state subnetstate.Enum, xerr fail.Error) {
	if rs.IsNull() {
		return subnetstate.UNKNOWN, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return subnetstate.UNKNOWN, fail.InvalidParameterError("task", "cannot be nil")
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
	if rs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
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
	gw, xerr = rs.GetGateway(task, true)
	if xerr != nil {
		return nil, xerr
	}
	primaryGatewayID := gw.GetID()

	// Get secondary gateway id if such a gateway exists
	gwIDs := []string{primaryGatewayID}
	gw, xerr = rs.GetGateway(task, false)
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
func (rs *subnet) BindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup, enabled resources.SecurityGroupActivation) fail.Error {
	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
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
func (rs *subnet) UnbindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) fail.Error {
	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
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
func (rs *subnet) ListSecurityGroups(task concurrency.Task, state securitygroupstate.Enum) (list []*propertiesv1.SecurityGroupBond, _ fail.Error) {
	var nullList []*propertiesv1.SecurityGroupBond
	if rs.IsNull() {
		return nullList, fail.InvalidInstanceError()
	}
	if task.IsNull() {
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
func (rs *subnet) EnableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) fail.Error {
	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	return rs.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
				return fail.NotFoundError("security group '%s' is not binded to subnet '%s'", sg.GetName(), rs.GetID())
			}

			// Do security group stuff to enable it
			if innerXErr := sg.BindToSubnet(task, rs, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrDuplicate:
					// security group already bound to subnet with the same state, consider as a success
				default:
					return innerXErr
				}
			}

			// update metadata
			nsgV1.ByID[sgID].Disabled = false
			return nil
		})
	})
}

// DisableSecurityGroup disables an already binded security group on subnet
func (rs *subnet) DisableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) fail.Error {
	if rs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	return rs.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// First check if the security group is not already registered for the host with the exact same state
			if _, ok := nsgV1.ByID[sgID]; !ok {
				return fail.NotFoundError("security group '%s' is not bound to subnet '%s'", sg.GetName(), rs.GetID())
			}

			// Do security group stuff to enable it
			if innerXErr := sg.BindToSubnet(task, rs, resources.SecurityGroupDisable, resources.KeepCurrentSecurityGroupMark); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
				// security group not bound to subnet, consider as a success
				default:
					return innerXErr
				}
			}

			// update metadata
			nsgV1.ByID[sgID].Disabled = true
			return nil
		})
	})
}

// InspectNetwork returns the resources.Network instance of parent Network of the Subnet
func (rs *subnet) InspectNetwork(task concurrency.Task) (resources.Network, fail.Error) {
	if rs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	var networkID string
	xerr := rs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		networkID = as.Network
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}
	if networkID == "" {
		return nil, fail.InconsistentError("metadata of subnet does not reference a parent Network")
	}

	return LoadNetwork(task, rs.GetService(), networkID)
}
