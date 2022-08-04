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

package common

import (
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/app/env"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// AssembleListenString constructs the listen string we will use in net.Listen()
func AssembleListenString(c *cli.Context, defaultHost, defaultPort string) string {
	// Value listen from parameters
	listen := c.String("listen")
	if listen == "" {
		listen, _, _ = env.FirstValue("SAFESCALED_LISTEN", "SAFESCALE_LISTEN", "SAFESCALE_SERVER")
	}
	if listen != "" {
		// Validate port part of the content of listen...
		parts := strings.Split(listen, ":")
		switch len(parts) {
		case 1:
			listen = parts[0] + ":" + defaultPort
		case 2:
			num, err := strconv.Atoi(parts[1])
			if err != nil || num <= 0 {
				logrus.Warnf("Parameter 'listen' content is invalid (port cannot be '%s'): ignored.", parts[1])
			}
		default:
			logrus.Warnf("Parameter 'listen' content is invalid, ignored.")
		}
	}
	// if listen is empty, get the port from env
	if listen == "" {
		port, _ := env.Value("SAFESCALED_PORT")
		if port != "" {
			num, err := strconv.Atoi(port)
			if err != nil || num <= 0 {
				logrus.Warnf("Environment variable 'SAFESCALED_PORT' contains invalid content ('%s'): ignored.", port)
			} else {
				listen = defaultHost + ":" + port
			}
		}

		// At last, if listen is empty, build it from defaults
		if listen == "" {
			listen = defaultHost + ":" + defaultPort
		}
	}

	return listen
}
