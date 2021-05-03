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
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	// MinimumMetadataVersion defines the version of the metadata recognized by the release
	// Must be incremented each time a new release requires upgrade of metadata (hopefully not for all new releases)
	// By convention, it corresponds to the SafeScale release that introduced the new format
	MinimumMetadataVersion = "v21.05.0"

	MustUpgradeMessage = "the current version of SafeSale binaries cannot use safely the current tenant metadata; you should consider to upgrade it using the command 'safescale tenant metadata upgrade %s'. Note however previous version of binaries would not be able to read safesly the newly created metadata ands should be upgraded everywhere."
	MustUpgradeBinaries = "the current version of SafeScale binaries requires the use of at least release %s to work correctly. Please upgrade your binaries"
)

// CheckMetadataVersion checks if the content of /version in metadata bucket is equal to MetadataVersion
func CheckMetadataVersion(svc iaas.Service) (string, fail.Error) {
	// Read file /version in metadata
	var currentMetadataVersion string

	// If version read is different than MetadataVersion, error
	result := strings.Compare(currentMetadataVersion, MinimumMetadataVersion)
	switch result {
	case -1:
		return currentMetadataVersion, fail.ForbiddenError(MustUpgradeMessage)
	case 1:
		return currentMetadataVersion, fail.ForbiddenError(MustUpgradeBinaries, MinimumMetadataVersion)
	}

	// everything is on-par
	return currentMetadataVersion, nil
}