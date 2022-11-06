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

package storage

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

// AbsolutePath returns the full path to reach the 'path'+'name' starting from the folder path
func AbsolutePath(basePath string, sep string, path ...string) string {
	for len(path) > 0 && (path[0] == "" || path[0] == ".") {
		path = path[1:]
	}
	var relativePath string
	for _, item := range path {
		if item != "" && item != sep {
			relativePath += sep + item
		}
	}
	relativePath = strings.Trim(relativePath, sep)
	if relativePath != "" {
		absolutePath := strings.ReplaceAll(relativePath, sep+sep, sep)
		if basePath != "" {
			absolutePath = basePath + sep + relativePath
			absolutePath = strings.ReplaceAll(absolutePath, sep+sep, sep)
		}
		return absolutePath
	}
	return basePath
}

// DetermineIfCryptIsEnabledInOptions tells if there is an option disabling encryption
func DetermineIfCryptIsEnabledInOptions(opts options.Options) (bool, fail.Error) {
	value, xerr := opts.Load(OptionDisableCrypt)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return true, nil
		default:
			return false, xerr
		}
	}

	switch casted := value.(type) {
	case bool:
		return !casted, nil
	case string:
		switch casted {
		case "true", "yes":
			return false, nil
		case "false", "no":
			return true, nil
		default:
			return false, fail.InconsistentError("content of '%s' option is incorrect", OptionDisableCrypt)
		}
	}

	return false, fail.InconsistentError("content of '%s' option is incorrect", OptionDisableCrypt)
}
