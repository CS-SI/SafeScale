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

package tracing

import (
	"strings"
)

// ShouldTrace tells if a specific trace is asked for
func ShouldTrace(key string) bool {
	if key = strings.TrimSpace(key); key == "" {
		return false
	}

	parts := strings.Split(key, ".")
	// If key.subkey is defined, return its value
	if len(parts) >= 2 {
		setting, ok := settings[parts[0]][parts[1]]
		if ok {
			return setting
		}
	}
	// If key is defined and there is no subkey, return true (key enabled as a whole)
	if _, ok := settings[parts[0]]; ok && len(settings[parts[0]]) == 0 {
		return true
	}
	return false
}
