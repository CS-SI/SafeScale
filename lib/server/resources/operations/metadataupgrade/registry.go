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

package metadataupgrade

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

type Mutator interface {
	Upgrade(iaas.Service, string, bool) fail.Error
}

type mutator struct {
	upgrader Mutator
	next     string
}

var (
	knownVersions = []string{
		"v20.06.0",
		"v21.05.0",
	}

	mutators = map[string]mutator{
		"v20.06.0": {
			upgrader: toV21_05_0{},
			next:     "v21.05.0",
		},
	}
)

// MutatorForVersion returns the function that can upgrade to version 'to'
func MutatorForVersion(version string) (Mutator, string, fail.Error) {
	if version == "" {
		return nil, "", fail.InvalidParameterCannotBeEmptyStringError("to")
	}

	item, ok := mutators[version]
	if ok {
		return item.upgrader, item.next, nil
	}

	return nil, "", fail.NotFoundError("failed to find a mutator for version '%s'", version)
}
