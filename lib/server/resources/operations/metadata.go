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

package operations

import (
	"strings"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

const (
	// MinimumMetadataVersion defines the version of the metadata recognized by the release
	// Must be incremented each time a new release requires upgrade of metadata (hopefully not for all new releases)
	// By convention, it corresponds to the SafeScale release that introduced the new format
	MinimumMetadataVersion = "v21.05.0"

	// FirstMetadataVersion corresponds to the first metadata format version
	FirstMetadataVersion = "v20.06.0"

	// MustUpgradeMessage  = "the current version of SafeScale binaries cannot use safely the current tenant metadata; you should consider upgrading the metadata using the command 'safescale tenant metadata upgrade %s'. Note that previous version of binaries would not be able to read safely the newly upgraded metadata and should be upgraded everywhere to at least version %s."
	MustUpgradeMessage  = "the current version of SafeScale binaries cannot use safely the current tenant metadata; you should consider upgrading the metadata using the command 'safescale tenant metadata upgrade %s'."
	MustUpgradeBinaries = "the current version of SafeScale binaries requires the use of at least release %s to work correctly. Please upgrade your binaries"
)

// CheckMetadataVersion checks if the content of /version in metadata bucket is equal to MetadataVersion
func CheckMetadataVersion(svc iaas.Service) (string, fail.Error) {
	// Read file /version in metadata
	var currentMetadataVersion string
	folder, xerr := NewMetadataFolder(svc, "")
	if xerr != nil {
		return "", xerr
	}

	xerr = folder.Read("/", "version", func(data []byte) fail.Error {
		currentMetadataVersion = string(data)
		return nil
	}, data.NewImmutableKeyValue("doNotCrypt", true),
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return "", fail.Wrap(xerr, "failed to read content of 'version' file in metadata bucket")
		}
	}
	if currentMetadataVersion == "" {
		currentMetadataVersion = FirstMetadataVersion
	}

	svcName, xerr := svc.GetName()
	if xerr != nil {
		return currentMetadataVersion, xerr
	}

	// If version read is different from MetadataVersion, error
	result := strings.Compare(currentMetadataVersion, MinimumMetadataVersion)
	switch result {
	case -1:
		return currentMetadataVersion, fail.ForbiddenError(MustUpgradeMessage, svcName)
	case 1:
		return currentMetadataVersion, fail.ForbiddenError(MustUpgradeBinaries, MinimumMetadataVersion)
	}

	// everything is ok
	return currentMetadataVersion, nil
}
