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

	clitools "github.com/CS-SI/SafeScale/v21/lib/utils/cli"
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
		if c.IsSet("cpu") {
			sizing = fmt.Sprintf("cpu ~ %d,", c.Int("cpu"))
		}
		if c.IsSet("cpufreq") {
			sizing += fmt.Sprintf("cpufreq >= %.01f,", c.Float64("cpufreq"))
		}
		if c.IsSet("gpu") {
			sizing += fmt.Sprintf("gpu = %d,", c.Int("gpu"))
		} else {
			sizing += "gpu = -1"
		}
		if c.IsSet("ram") {
			sizing += fmt.Sprintf("ram ~ %.01f,", c.Float64("ram"))
		}
		if c.IsSet("disk") {
			sizing += fmt.Sprintf("disk >= %.01f,", c.Float64("disk"))
		}
		if c.IsSet("count") {
			sizing += fmt.Sprintf("count = %d", c.Int("count"))
		}
	}
	return sizing, nil

	// VPL: this code has to move to listeners.Cluster, or resources.operations.cluster
	// tokens, err := clitools.ParseParameter(sizing)
	// if err != nil {
	// 	return nil, clitools.FailureResponse(clitools.ExitOnInvalidArgument(err.Error())
	// }

	// def := protocol.HostDefinition{
	// 	Name:    c.Args().First(),
	// 	ImageId: c.String("os"),
	// 	Networking: c.String("net"),
	// 	Public:  c.Bool("public"),
	// 	Force:   c.Bool("force"),
	// 	Sizing:  &protocol.HostSizing{},
	// }
	// if t, ok := tokens["cpu"]; ok {
	// 	min, max, err := t.Validate()
	// 	if err != nil {
	// 		return nil, clitools.FailureResponse(clitools.ExitOnInvalidArgument(err.Error())
	// 	}
	// 	if min != "" {
	// 		val, _ := strconv.ParseFloat(min, 64)
	// 		def.Sizing.MinCpuCount = int32(val)
	// 	}
	// 	if max != "" {
	// 		val, _ := strconv.Atoi(max)
	// 		def.Sizing.MaxCpuCount = int32(val)
	// 	}
	// }
	// var count uint
	// if t, ok := tokens["count"]; ok {
	// 	c, _, err := t.Validate()
	// 	if err != nil {
	// 		return nil, clitools.FailureResponse(clitools.ExitOnInvalidArgument(err.Error())
	// 	}
	// 	temp, _ := strconv.Atoi(c)
	// 	count = uint(temp)
	// }
	// if t, ok := tokens["cpufreq"]; ok {
	// 	min, _, err := t.Validate()
	// 	if err != nil {
	// 		return nil, clitools.FailureResponse(clitools.ExitOnInvalidArgument(err.Error())
	// 	}
	// 	if min != "" {
	// 		val, _ := strconv.ParseFloat(min, 64)
	// 		def.Sizing.MinCpuFreq = float32(val)
	// 	}
	// }
	// if t, ok := tokens["gpu"]; ok {
	// 	min, _, err := t.Validate()
	// 	if err != nil {
	// 		return nil, clitools.FailureResponse(clitools.ExitOnInvalidArgument(err.Error())
	// 	}
	// 	if min != "" {
	// 		val, _ := strconv.Atoi(min)
	// 		def.Sizing.GpuCount = int32(val)
	// 	}
	// } else {
	// 	def.Sizing.GpuCount = -1
	// }
	// if t, ok := tokens["ram"]; ok {
	// 	min, max, err := t.Validate()
	// 	if err != nil {
	// 		return nil, clitools.FailureResponse(clitools.ExitOnInvalidArgument(err.Error())
	// 	}
	// 	if min != "" {
	// 		val, _ := strconv.ParseFloat(min, 64)
	// 		def.Sizing.MinRamSize = float32(val)
	// 	}
	// 	if max != "" {
	// 		val, _ := strconv.ParseFloat(max, 64)
	// 		def.Sizing.MaxRamSize = float32(val)
	// 	}
	// }
	// if t, ok := tokens["disk"]; ok {
	// 	min, _, err := t.Validate()
	// 	if err != nil {
	// 		return nil, clitools.FailureResponse(clitools.ExitOnInvalidArgument(err.Error())
	// 	}
	// 	if min != "" {
	// 		val, _ := strconv.Atoi(min)
	// 		def.Sizing.MinDiskSize = int32(val)
	// 	}
	// }
	// return &def, count, nil
}
