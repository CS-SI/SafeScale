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

package temporal

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// MaxTimeout return the maximum of timeouts 'a' and 'b'
func MaxTimeout(a time.Duration, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// getFromEnv reads an environment variable 'string', interprets the variable as a time.Duration if possible and returns the time to the caller
// if there is a failure, it returns a default duration 'duration' passed as an argument when calling the function
func getFromEnv(fallbackDuration time.Duration, keys ...string) time.Duration {
	for _, key := range keys {
		if defaultTimeoutCandidate := os.Getenv(key); defaultTimeoutCandidate != "" {
			newTimeout, err := time.ParseDuration(defaultTimeoutCandidate)
			if err != nil {
				logrus.Warnf("Error parsing variable: [%s]", key)
				continue
			}
			return newTimeout
		}
	}

	return fallbackDuration
}
