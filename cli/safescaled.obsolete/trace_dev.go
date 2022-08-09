//go:build ignore && !release
// +build ignore,!release

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

package main

// appTrace contains the default parts that we want to trace
func appTrace() string {
	return `
{
    "concurrency": {
        "lock": false,
        "task": false
    },
    "ssh": {},
    "listeners": {},
    "handlers": {},
    "resources": {
        "cluster": true
    }
}`
}
