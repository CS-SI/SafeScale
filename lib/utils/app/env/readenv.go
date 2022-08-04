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

package env

import (
	"os"
	"strings"
)

var (
	envVars = map[string]string{}
)

// Value returns the value associated with key(s)
func Value(key string) (string, bool) {
	val, _, ok := FirstValue(key)
	return val, ok
}

// FirstValue returns the value of the first defined variable in the order of keys
// returns:
//    - "", "", false if no var has been found
//    - value, varname, true if a variable has been found
func FirstValue(keys ...string) (string, string, bool) {
	for _, v := range keys {
		value, ok := envVars[v]
		if ok {
			return value, v, ok
		}
	}
	return "", "", false
}

// Lookup tells if an environment variable with the key exists
func Lookup(key string) bool {
	_, ok := envVars[key]
	return ok
}

// Keys returns the keys in environment
func Keys(options ...Option) (list []string, err error) {
	var opts _options
	for _, v := range options {
		err = v(&opts)
		if err != nil {
			return nil, err
		}
	}
	filter := buildFilter(opts)

	list = make([]string, len(envVars), 0)
	for k := range envVars {
		if filter(k) {
			list = append(list, k)
		}
	}
	return list, nil
}

func loadEnvVars() {
	all := os.Environ()

	for _, v := range all {
		splitted := strings.Split(v, "=")
		envVars[splitted[0]] = splitted[1]
	}
}

func init() {
	loadEnvVars()
}
