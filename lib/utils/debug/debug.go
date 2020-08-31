/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package debug

import (
    "encoding/json"
    "os"
    "strings"

    "github.com/CS-SI/SafeScale/lib/utils/scerr"
)

var settings map[string]map[string]struct{} = nil

// RegisterTraceSettings keeps track of what has to be traced
func RegisterTraceSettings(jsonSettings string) error {
    if settings != nil {
        return scerr.DuplicateError("trace settings are already defined")
    }

    newSettings := map[string]map[string]struct{}{}
    err := json.Unmarshal([]byte(jsonSettings), &newSettings)
    if err != nil {
        return scerr.Wrap(scerr.SyntaxError(err.Error()), "no trace are enabled, an error occured loading trace settings")
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
            if _, ok := newSettings[keys[0]]; !ok {
                newSettings[key] = map[string]struct{}{}
            }
            if len(keys) > 1 {
                subkey := strings.TrimSpace(keys[1])
                newSettings[key][subkey] = struct{}{}
            }
        }
    }

    settings = newSettings
    return nil
}

// IfTrace tells if a specific trace is asked for
func IfTrace(key string) bool {
    if key == "" {
        return false
    }
    parts := strings.Split(key, ".")
    // If key.subkey is defined, return true
    if len(parts) >= 2 {
        _, ok := settings[parts[0]][parts[1]]
        if ok {
            return true
        }
    }
    // If key is defined and there is no subkey, return true (key enabled as a whole)
    if _, ok := settings[parts[0]]; ok && len(settings[parts[0]]) == 0 {
        return true
    }
    return false
}
