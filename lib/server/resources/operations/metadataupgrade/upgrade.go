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
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	FirstMetadataVersion = "v20.06.0"
)

// Upgrade realizes the metadata upgrade from version 'from' to version 'to'
func Upgrade(svc iaas.Service, from, to string, dryRun, doNotBackup bool) fail.Error {
	if from == "" {
		from = FirstMetadataVersion
	}
	if to == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("to")
	}
	if strings.Compare(from, to) > 0 {
		return fail.InvalidParameterError("from/to", "'from' is greater than or equal to 'to'")
	}

	// if !doNotBackup {
	// 	xerr := BackupMetadata(svc, "")
	// 	xerr = debug.InjectPlannedFail(xerr)
	// 	if xerr != nil {
	// 		return fail.Wrap(xerr, "failed to backup metadata before upgrade")
	// 	}
	// }

	// -- check mutators are all available
	var (
		mutatorList     []Mutator
		fromVersionList []string
	)
	for {
		fn, next, xerr := MutatorForVersion(from)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				return fail.NotFoundError("failed to find a way to upgrade metadata from version %s", from)
			default:
				return xerr
			}
		}
		if fn == nil {
			return fail.InconsistentError("got nil mutator to upgrade metadata from version %s to version %s", from, next)
		}

		mutatorList = append(mutatorList, fn)
		fromVersionList = append(fromVersionList, from)
		if next == to {
			break
		}

		from = next
	}

	for k, fn := range mutatorList {
		xerr := fn.Upgrade(svc, fromVersionList[k], dryRun)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr)
		}
	}

	// -- at last, update version entry in metadata --
	folder, xerr := operations.NewMetadataFolder(svc, "")
	if xerr != nil {
		return xerr
	}

	xerr = folder.Write("", "version", []byte(to), data.NewImmutableKeyValue("doNotCrypt", true))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to update content of '/version' file in metadata bucket")
	}

	return nil
}

// BackupMetadata creates a tar.gz archive of svc metadata content, with current date/time in name
func BackupMetadata(svc iaas.Service, filename string) fail.Error {
	if filename == "" {
		filename = fmt.Sprintf("safescale.%s-metadata.backup", svc.GetName())
	}

	return fail.NotImplementedError()
}
