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

package stacks

import (
	"context"
	"fmt"
	"os"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	uuid "github.com/gofrs/uuid"
)

// HostParameter can represent a host by a string (containing name or id), an *abstract.HostCore or an *abstract.HostFull
type HostParameter interface{}

// ValidateHostParameter validates host parameter that can be a string as ID or an *abstract.HostCore
func ValidateHostParameter(ctx context.Context, hostParam HostParameter) (ahf *abstract.HostFull, hostLabel string, ferr fail.Error) {
	ahf = abstract.NewHostFull()
	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, "", fail.InvalidParameterCannotBeEmptyStringError("hostParam")
		}
		ahf.Core.ID = hostParam
		hostLabel = hostParam
	case *abstract.HostCore:
		if valid.IsNil(hostParam) {
			return nil, "", fail.InvalidParameterError("hostParam", "cannot be *abstract.HostCore null value")
		}
		ahf.Core = hostParam
		if ahf.Core.Name != "" {
			hostLabel = "'" + ahf.Core.Name + "'"
		} else {
			hostLabel = ahf.Core.ID
		}
	case *abstract.HostFull:
		if valid.IsNil(hostParam) {
			return nil, "", fail.InvalidParameterError("hostParam", "cannot be *abstract.HostFull null value")
		}
		ahf = hostParam
		if ahf.Core.Name != "" {
			hostLabel = "'" + ahf.Core.Name + "'"
		} else {
			hostLabel = ahf.Core.ID
		}
	default:
		return nil, "", fail.InvalidParameterError("hostParam", "valid types are non-empty string, *abstract.HostCore or *abstract.HostFull")
	}
	if hostLabel == "" {
		return nil, "", fail.InvalidParameterError("hostParam", "at least one of fields 'ID' or 'Name' must not be empty string")
	}
	// if ahf.Core.ID == "" {
	// 	return nil, "", fail.InvalidParameterError("hostParam", "field ID cannot be empty string")
	// }
	return ahf, hostLabel, nil
}

// ProvideCredentialsIfNeeded ...
func ProvideCredentialsIfNeeded(request *abstract.HostRequest) (ferr fail.Error) {
	if request == nil {
		return fail.InvalidParameterCannotBeNilError("request")
	}

	// If no key pair is supplied create one
	if request.KeyPair == nil {
		id, err := uuid.NewV4()
		if err != nil {
			return fail.Wrap(err, "failed to create host UUID")
		}

		var xerr fail.Error
		name := fmt.Sprintf("%s_%s", request.ResourceName, id)
		if request.KeyPair, xerr = abstract.NewKeyPair(name); xerr != nil {
			return fail.Wrap(xerr, "failed to create Host key pair")
		}
	}

	// If no password is supplied, generate one
	if request.Password == "" {
		request.Password = os.Getenv("SAFESCALE_UNSAFE_PASSWORD")
		if request.Password == "" {
			password, err := utils.GeneratePassword(16)
			if err != nil {
				return fail.Wrap(err, "failed to generate operator password")
			}
			request.Password = password
		}
	}

	return nil
}
