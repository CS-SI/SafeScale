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

package utils

import (
	"os"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// LazyRemove is identical to os.Remove, but doesn't raise an error, and
// log.Warn every error except "file not found" which is ignored
func LazyRemove(path string) fail.Error {
	if err := os.Remove(path); err != nil {
		switch err.(type) {
		case *os.PathError:
			// File not found, that's ok because we wanted to remove it...
		default:
			logrus.Errorf("LazyRemove(): err is type '%s'", reflect.TypeOf(err).String())
			return fail.Wrap(err, "failed to remove file '%s'", path)
		}
	}
	return nil
}
