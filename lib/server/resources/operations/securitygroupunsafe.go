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
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/errcontrol"
	"golang.org/x/net/context"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	"github.com/sirupsen/logrus"
)

// delete effectively remove a Security Group
func (instance *securityGroup) unsafeDelete(ctx context.Context, force bool) fail.Error {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	svc := instance.GetService()
	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if !force {
			// check bonds to hosts
			innerXErr := props.Inspect(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				hostsV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				// Do not remove a securityGroup used on hosts
				hostCount := len(hostsV1.ByName)
				if hostCount > 0 {
					keys := make([]string, 0, hostCount)
					for k := range hostsV1.ByName {
						keys = append(keys, k)
					}
					return fail.NotAvailableError("security group '%s' is currently bound to %d host%s: %s", instance.GetName(), hostCount, strprocess.Plural(uint(hostCount)), strings.Join(keys, ","))
				}

				// Do not remove a Security Group marked as default for a host
				if hostsV1.DefaultFor != "" {
					if _, xerr := LoadHost(svc, hostsV1.DefaultFor); xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							hostsV1.DefaultFor = ""
							// clear the field and continue, the host does not exist anymore
						default:
							return xerr
						}
					}
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			// check bonds to subnets
			innerXErr = props.Inspect(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
				subnetsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				// Do not remove a securityGroup used on subnet(s)
				subnetCount := len(subnetsV1.ByID)
				if subnetCount > 0 {
					keys := make([]string, subnetCount)
					for k := range subnetsV1.ByName {
						if task.Aborted() {
							return fail.AbortedError(nil, "aborted")
						}

						keys = append(keys, k)
					}
					return fail.NotAvailableError("security group is currently bound to %d subnet%s: %s", subnetCount, strprocess.Plural(uint(subnetCount)), strings.Join(keys, ","))
				}

				// Do not remove a Security Group marked as default for a subnet
				if subnetsV1.DefaultFor != "" {
					subnetInstance, xerr := LoadSubnet(svc, "", subnetsV1.DefaultFor)
					xerr = errcontrol.CrasherFail(xerr)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							// clear the field and continue, the subnet does not exist anymore
							subnetsV1.DefaultFor = ""
						default:
							return xerr
						}
					} else {
						subnetInstance.Released()
					}
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		// FIXME: how to restore bindings in case of failure or abortion ? This would prevent the use of DisarmAbortSignal here...
		// defer task.DisarmAbortSignal()()

		// First unbind from subnets (which will unbind from hosts attached to these subnets...)
		innerXErr := props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgnV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return instance.unbindFromSubnets(ctx, sgnV1)
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Second, unbind from the hosts if there are remaining ones
		innerXErr = props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return instance.unbindFromHosts(ctx, sghV1)
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Conditions are met, delete securityGroup
		// FIXME: communication failure handled at service level, not necessary anymore to retry here
		return netretry.WhileCommunicationUnsuccessfulDelay1Second(
			func() error {
				if innerXErr := svc.DeleteSecurityGroup(asg); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			temporal.GetCommunicationTimeout(),
		)
	})
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			xerr = fail.ConvertError(xerr.Cause())
		default:
		}
	}
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider a Security Group not found as a successful deletion
		default:
			return xerr
		}
	}

	// // Again, if we arrive here, we want the deletion of metadata not to be interrupted by abort, it's too late
	// defer task.DisarmAbortSignal()()

	// Deletes metadata from Object Storage
	if xerr = instance.core.delete(); xerr != nil {
		// If entry not found, considered as a success
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.Tracef("core not found, deletion considered as a success")
			// continue
		default:
			return xerr
		}
	}

	// newSecurityGroup := nullSecurityGroup()
	// *instance = *newSecurityGroup
	return nil
}

// unsafeClear is the non goroutine-safe implementation for Clear, that does the real work faster (no locking, less if no parameter validations)
// Note: must be used wisely
func (instance *securityGroup) unsafeClear(task concurrency.Task) fail.Error {
	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		_, innerXErr := instance.GetService().ClearSecurityGroup(asg)
		return innerXErr
	})
}

// unsafeAddRule adds a rule to a security group
func (instance *securityGroup) unsafeAddRule(task concurrency.Task, rule *abstract.SecurityGroupRule) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rule.IsNull() {
		return fail.InvalidParameterError("rule", "cannot be null value of 'abstract.SecurityGroupRule'")
	}

	return instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		asg, ok := clonable.(*abstract.SecurityGroup)
		if !ok {
			return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		newAsg, innerXErr := instance.GetService().AddRuleToSecurityGroup(asg, rule)
		if innerXErr != nil {
			return innerXErr
		}

		asg.Replace(newAsg)
		return nil
	})
}
