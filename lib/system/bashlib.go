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

package system

import (
	"math"
	"strings"
	"sync/atomic"
	"time"

	rice "github.com/GeertJohan/go.rice"

	"github.com/CS-SI/SafeScale/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate rice embed-go

const (
	BashLibraryReservedKeyword            = "reserved_BashLibrary"
	DefaultDelayReservedKeyword           = "reserved_DefaultDelay"
	DefaultTimeoutReservedKeyword         = "reserved_DefaultTimeout"
	LongTimeoutReservedKeyword            = "reserved_LongTimeout"
	ClusterJoinTimeoutReservedKeyword     = "reserved_ClusterJoinTimeout"
	DockerImagePullTimeoutReservedKeyword = "reserved_DockerImagePullTimeout"
)

// bashLibrayContent contains the content of the script bash_library.sh, that will be injected inside scripts through parameter {{.reserved_BashLibrary}}
var bashLibraryContent atomic.Value

type BashLibraryDefinition struct {
	Content                string `json:"reserved_BashLibrary"`
	DefaultDelay           uint   `json:"reserved_DefaultDelay"`
	DefaultTimeout         string `json:"reserved_DefaultTimeout"`
	LongTimeout            string `json:"reserved_LongTimeout"`
	ClusterJoinTimeout     string `json:"reserved_ClusterJoinTimeout"`
	DockerImagePullTimeout string `json:"reserved_DockerImagePullTimeout"`
}

// BuildBashLibraryDefinition generates the content of {{.reserved_BashLibrary}} and other reserved template variables
func BuildBashLibraryDefinition() (*BashLibraryDefinition, fail.Error) {
	anon := bashLibraryContent.Load()
	if anon == nil {
		box, err := rice.FindBox("../system/scripts")
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		// get file contents as string
		tmplContent, err := box.String("bash_library.sh")
		if err != nil {
			return nil, fail.ConvertError(err)
		}
		bashLibraryContent.Store(tmplContent)
		anon = bashLibraryContent.Load()
	}

	out := &BashLibraryDefinition{
		Content: anon.(string),
		// Sets delays and timeouts for script
		DefaultDelay:           uint(math.Ceil(2 * temporal.GetDefaultDelay().Seconds())),
		DefaultTimeout:         strings.Replace((temporal.GetHostTimeout() / 2).Truncate(time.Minute).String(), "0s", "", -1),
		LongTimeout:            strings.Replace(temporal.GetLongOperationTimeout().Truncate(time.Minute).String(), "0s", "", -1),
		ClusterJoinTimeout:     strings.Replace(temporal.GetLongOperationTimeout().Truncate(time.Minute).String(), "0s", "", -1),
		DockerImagePullTimeout: strings.Replace((2 * temporal.GetHostTimeout()).Truncate(time.Minute).String(), "0s", "", -1),
	}
	return out, nil
}

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
