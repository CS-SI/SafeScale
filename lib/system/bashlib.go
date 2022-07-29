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

package system

import (
	_ "embed"
	"math"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

const (
	BashLibraryReservedKeyword            = "reserved_BashLibrary"
	DefaultDelayReservedKeyword           = "reserved_DefaultDelay"
	DefaultTimeoutReservedKeyword         = "reserved_DefaultTimeout"
	LongTimeoutReservedKeyword            = "reserved_LongTimeout"
	ClusterJoinTimeoutReservedKeyword     = "reserved_ClusterJoinTimeout"
	DockerImagePullTimeoutReservedKeyword = "reserved_DockerImagePullTimeout"
)

type BashLibraryDefinition struct {
	Content                string `json:"reserved_BashLibrary"`
	DefaultDelay           uint   `json:"reserved_DefaultDelay"`
	DefaultTimeout         string `json:"reserved_DefaultTimeout"`
	LongTimeout            string `json:"reserved_LongTimeout"`
	ClusterJoinTimeout     string `json:"reserved_ClusterJoinTimeout"`
	DockerImagePullTimeout string `json:"reserved_DockerImagePullTimeout"`
}

//go:embed scripts/bash_library.sh
var bashLibrary string

// BuildBashLibraryDefinition generates the content of {{.reserved_BashLibrary}} and other reserved template variables
func BuildBashLibraryDefinition(
	timings temporal.Timings,
) (*BashLibraryDefinition, fail.Error) {
	out := &BashLibraryDefinition{
		Content: bashLibrary,
		// Sets delays and timeouts for script
		DefaultDelay:           uint(math.Ceil(2 * timings.NormalDelay().Seconds())),
		DefaultTimeout:         strings.ReplaceAll((timings.HostOperationTimeout() / 2).Truncate(time.Minute).String(), "0s", ""),
		LongTimeout:            strings.ReplaceAll(timings.HostLongOperationTimeout().Truncate(time.Minute).String(), "0s", ""),
		ClusterJoinTimeout:     strings.ReplaceAll(timings.HostLongOperationTimeout().Truncate(time.Minute).String(), "0s", ""),
		DockerImagePullTimeout: strings.ReplaceAll((2 * timings.HostOperationTimeout()).Truncate(time.Minute).String(), "0s", ""),
	}
	return out, nil
}

// ToMap transforms bld to a map
func (bld *BashLibraryDefinition) ToMap() (map[string]interface{}, fail.Error) {
	empty := map[string]interface{}{}
	if bld == nil {
		return empty, fail.InvalidParameterCannotBeNilError("bld")
	}

	out := map[string]interface{}{}
	jsoned, err := json.Marshal(*bld)
	if err != nil {
		return empty, fail.Wrap(err, "failed to convert BashLibraryDefinition to JSON")
	}

	err = json.Unmarshal(jsoned, &out)
	if err != nil {
		return empty, fail.Wrap(err, "failed to convert BashLibraryDefinition from JSON to map")
	}

	return out, nil
}
