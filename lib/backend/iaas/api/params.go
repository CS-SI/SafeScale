/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package iaasapi

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type (
	// NetworkParameter can represent a network by a string (containing name or id) or an *abstract.Network
	NetworkParameter any

	// SubnetParameter can represent a Subnet by a string (containing name or id) or an *abstract.Subnet
	SubnetParameter any

	// SecurityGroupParameter can represent a Security Group by a string as ID or an *abstract.SecurityGroup
	SecurityGroupParameter any

	// HostParameter can represent a host by a string (containing name or id), an *abstract.HostCore or an *abstract.HostFull
	HostParameter any
)

// ValidateNetworkParameter validates host parameter that can be a string as ID or an *abstract.Network
func ValidateNetworkParameter(networkParam NetworkParameter) (an *abstract.Network, networkLabel string, ferr fail.Error) {
	an = nil
	switch networkParam := networkParam.(type) {
	case string:
		if networkParam == "" {
			return nil, "", fail.InvalidParameterCannotBeEmptyStringError("networkParam")
		}
		an.ID = networkParam
		networkLabel = networkParam
	case *abstract.Network:
		if valid.IsNil(networkParam) {
			return nil, "", fail.InvalidParameterError("networkParam", "cannot be *abstract.Network null value")
		}

		var err error
		an, err = clonable.CastedClone[*abstract.Network](networkParam)
		if err != nil {
			return nil, "", fail.Wrap(err)
		}
		if an.Name != "" {
			networkLabel = "'" + an.Name + "'"
		} else {
			networkLabel = an.ID
		}

	default:
		return nil, "", fail.InvalidParameterError("networkParam", "valid types are non-empty string, *abstract.Network")
	}

	if networkLabel == "" {
		return nil, "", fail.InvalidParameterError("networkParam", "at least one of fields 'ID' or 'Name' must not be empty string")
	}
	return an, networkLabel, nil
}

// ValidateSubnetParameter validates Subnet parameter that can be a string as ID or an *abstract.Subnet
func ValidateSubnetParameter(subnetParam SubnetParameter) (as *abstract.Subnet, subnetLabel string, ferr fail.Error) {
	as = nil
	switch subnetParam := subnetParam.(type) {
	case string:
		if subnetParam == "" {
			return nil, "", fail.InvalidParameterCannotBeEmptyStringError("networkParam")
		}
		as.ID = subnetParam
		subnetLabel = subnetParam

	case *abstract.Subnet:
		if valid.IsNil(subnetParam) {
			return nil, "", fail.InvalidParameterError("networkParam", "cannot be *abstract.Network null value")
		}

		var err error
		as, err = clonable.CastedClone[*abstract.Subnet](subnetParam)
		if err != nil {
			return nil, "", fail.Wrap(err)
		}

		if as.Name != "" {
			subnetLabel = "'" + as.Name + "'"
		} else {
			subnetLabel = as.ID
		}

	default:
		return nil, "", fail.InvalidParameterError("networkParam", "valid types are non-empty string, *abstract.Network")
	}

	if subnetLabel == "" {
		return nil, "", fail.InvalidParameterError("networkParam", "at least one of fields 'ID' or 'Name' must not be empty string")
	}
	return as, subnetLabel, nil
}

// ValidateHostParameter validates host parameter that can be a string as ID or an *abstract.HostCore
func ValidateHostParameter(hostParam HostParameter) (ahf *abstract.HostFull, hostLabel string, ferr fail.Error) {
	ahf = nil
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, "", fail.InvalidParameterCannotBeEmptyStringError("hostParam")
		}

		ahf.ID = hostParam
		hostLabel = hostParam
	case *abstract.HostCore:
		if valid.IsNil(hostParam) {
			return nil, "", fail.InvalidParameterError("hostParam", "cannot be *abstract.HostCore null value")
		}

		ahf.HostCore = hostParam
		if ahf.Name != "" {
			hostLabel = "'" + ahf.Name + "'"
		} else {
			hostLabel = ahf.ID
		}
	case *abstract.HostFull:
		if valid.IsNil(hostParam) {
			return nil, "", fail.InvalidParameterError("hostParam", "cannot be *abstract.HostFull null value")
		}

		ahf = hostParam
		if ahf.Name != "" {
			hostLabel = "'" + ahf.Name + "'"
		} else {
			hostLabel = ahf.ID
		}
	default:
		return nil, "", fail.InvalidParameterError("hostParam", "valid types are non-empty string, *abstract.HostCore or *abstract.HostFull")
	}
	if hostLabel == "" {
		return nil, "", fail.InvalidParameterError("hostParam", "at least one of fields 'ID' or 'Name' must not be empty string")
	}

	return ahf, hostLabel, nil
}

// ValidateSecurityGroupParameter validates securitygroup parameter that can be a string as ID or an *abstract.SecurityGroup
func ValidateSecurityGroupParameter(sgParam SecurityGroupParameter) (asg *abstract.SecurityGroup, sgLabel string, _ fail.Error) {
	asg = abstract.NewSecurityGroup()
	switch sgParam := sgParam.(type) {
	case string:
		if sgParam == "" {
			return asg, "", fail.InvalidParameterCannotBeEmptyStringError("sgaram")
		}
		asg.ID = sgParam
		sgLabel = asg.ID
	case *abstract.SecurityGroup:
		if valid.IsNil(sgParam) {
			return asg, "", fail.InvalidParameterError("sgParam", "cannot be *abstract.ScurityGroup null value")
		}
		asg = sgParam
		if asg.Name != "" {
			sgLabel = "'" + asg.Name + "'"
		} else {
			sgLabel = asg.ID
		}
	default:
		return asg, "", fail.InvalidParameterError("sgParam", "valid types are non-empty string or *abstract.SecurityGroup")
	}
	return asg, sgLabel, nil
}
