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
	"fmt"
	"os"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
)

var settings map[string]map[string]bool

// RegisterTraceSettings keeps track of what has to be traced
func RegisterTraceSettings(jsonSettings string) error { // FIXME: Delete this
	if settings != nil {
		return fmt.Errorf("trace settings are already defined")
	}

	newSettings := map[string]map[string]bool{}
	err := json.Unmarshal([]byte(jsonSettings), &newSettings)
	if err != nil {
		return fmt.Errorf("no trace are enabled, an error occurred loading trace settings: %w", err)
	}

	// Check with env variable SAFESCALE_TRACE if key or key.subkey is inside
	if env := os.Getenv("SAFESCALE_TRACE"); env != "" {
		parts := strings.Split(env, ",")
		for _, part := range parts {
			if part == "" {
				continue
			}
			keys := strings.Split(strings.TrimSpace(part), ".")
			key := strings.TrimSpace(keys[0])
			reverse := false
			if key[0] == '!' {
				key = key[1:]
				reverse = true
			}

			keysLength := len(keys)
			if _, ok := newSettings[key]; !ok || (keysLength == 1 && !reverse) {
				newSettings[key] = map[string]bool{}
			} else if ok && keysLength == 1 && reverse {
				delete(newSettings, key)
			}
			if keysLength > 1 {
				subkey := strings.TrimSpace(keys[1])
				newSettings[key][subkey] = true
			}
		}
	}

	settings = newSettings
	return nil
}
