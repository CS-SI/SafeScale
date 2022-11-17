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
	"fmt"
	"os"

	uuid "github.com/gofrs/uuid"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

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
