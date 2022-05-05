//go:build disabled
// +build disabled

// //go:build integrationtests
// // +build integrationtests

/*
go:build integrationtests
 +build integrationtests
*/
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

package providers

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Enum represents the provider of the tested driver
type Enum int

const (
	UNKNOWN Enum = iota
	OVH
	CLOUDFERRO
	FLEXIBLEENGINE
	AWS
	GCP
	OUTSCALE
)

func (e Enum) Key() string {
	switch e {
	case OVH:
		return "TEST_OVH"
	case CLOUDFERRO:
		return "TEST_CLOUDFERRO"
	case FLEXIBLEENGINE:
		return "TEST_FLEXIBLEENGINE"
	case AWS:
		return "TEST_AWS"
	case GCP:
		return "TEST_GCP"
	case OUTSCALE:
		return "TEST_OUTSCALE"
	}
	return ""
}

func (e Enum) Name() string {
	switch e {
	case OVH:
		return "ovh"
	case CLOUDFERRO:
		return "cloudferro"
	case FLEXIBLEENGINE:
		return "flexibleengine"
	case AWS:
		return "aws"
	case GCP:
		return "gcp"
	case OUTSCALE:
		return "outscale"
	}
	return ""
}

func FromString(str string) (Enum, error) {
	switch strings.ToLower(str) {
	case "ovh":
		return OVH, nil
	case "cloudferro":
		return CLOUDFERRO, nil
	case "flexibleengine":
		return FLEXIBLEENGINE, nil
	case "aws":
		return AWS, nil
	case "gcp":
		return GCP, nil
	case "outscale":
		return OUTSCALE, nil
	}

	return UNKNOWN, fail.NotFoundError("%s is not a valid Provider", str)
}
