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

package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/denisbrodbeck/machineid"
	"github.com/urfave/cli"

	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
)

// GenerateClientIdentity builds a string identifying the client
func GenerateClientIdentity() string {
	id, _ := machineid.ProtectedID("safescale:" + strconv.Itoa(os.Getuid()))
	return id
}

// constructHostDefinitionStringFromCLI ...
func constructHostDefinitionStringFromCLI(c *cli.Context, key string) (string, error) {
	var sizing string
	if c.IsSet(key) {
		if c.IsSet("cpu") || c.IsSet("cpufreq") || c.IsSet("gpu") || c.IsSet("ram") || c.IsSet("disk") {
			return "", clitools.FailureResponse(clitools.ExitOnInvalidArgument(fmt.Sprintf("cannot use simultaneously --%s and --cpu|--cpufreq|--gpu|--ram|--disk", key)))
		}
		sizing = c.String(key)
		splitted := strings.Split(key, ",")
		found := false
		for _, v := range splitted {
			if strings.HasPrefix(v, "gpu") {
				found = true
				break
			}
		}
		if !found {
			if sizing != "" {
				sizing += ","
			}
			sizing += "gpu = -1"
		}
	} else {
		var fragments []string
		if c.IsSet("cpu") {
			fragments = append(fragments, fmt.Sprintf("cpu ~ %d", c.Int("cpu")))
		}
		if c.IsSet("cpufreq") {
			fragments = append(fragments, fmt.Sprintf("cpufreq >= %.01f", c.Float64("cpufreq")))
		}
		if c.IsSet("gpu") {
			fragments = append(fragments, fmt.Sprintf("gpu = %d", c.Int("gpu")))
		} else {
			fragments = append(fragments, "gpu = -1")
		}
		if c.IsSet("ram") {
			fragments = append(fragments, fmt.Sprintf("ram ~ %.01f", c.Float64("ram")))
		}
		if c.IsSet("disk") {
			fragments = append(fragments, fmt.Sprintf("disk >= %.01f", c.Float64("disk")))
		}
		if c.IsSet("count") {
			fragments = append(fragments, fmt.Sprintf("count = %d", c.Int("count")))
		}

		sizing = strings.Join(fragments, ",")
	}
	return sizing, nil
}
