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
	"os"
	"strconv"
	"strings"

	"github.com/denisbrodbeck/machineid"
	"github.com/spf13/cobra"
)

// GenerateClientIdentity builds a string identifying the client
func GenerateClientIdentity() string {
	id, _ := machineid.ProtectedID("safescale:" + strconv.Itoa(os.Getuid()))
	return id
}

// constructHostDefinitionStringFromCLI ...
func constructHostDefinitionStringFromCLI(c *cobra.Command, key string) (string, error) {
	sizing, err := c.Flags().GetString(key)
	if err != nil {
		return "", err
	}

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
	return sizing, nil
}
