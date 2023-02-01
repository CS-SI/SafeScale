/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// PublicIPParameter can represent a PublicIP by a string as ID or an *abstract.PublicIP
type PublicIPParameter interface{}

// ValidatePublicIParameter validates 'pipParam' parameter, that can be a string as ID or an *abstract.PublicIP
func ValidatePublicIParameter(pipParam PublicIPParameter) (apip *abstract.PublicIP, pipLabel string, _ fail.Error) {
	apip = abstract.NewPublicIP()
	switch casted := pipParam.(type) {
	case string:
		if casted == "" {
			return apip, "", fail.InvalidParameterCannotBeEmptyStringError("pipParam")
		}

		apip.ID = casted
		pipLabel = apip.ID
	case *abstract.PublicIP:
		if valid.IsNil(casted) {
			return apip, "", fail.InvalidParameterError("pipParam", "cannot be *abstract.PublicIP null value")
		}
		apip = casted
		if apip.Name != "" {
			pipLabel = "'" + apip.Name + "'"
		} else {
			pipLabel = apip.ID
		}
	default:
		return apip, "", fail.InvalidParameterError("pipParam", "valid types are non-empty string or *abstract.PublicIP")
	}
	return apip, pipLabel, nil
}
