/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package cmd

import (
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/safescale/client"
	"github.com/CS-SI/SafeScale/utils"
	clitools "github.com/CS-SI/SafeScale/utils"
)

// DataCmd command
var DataCmd = cli.Command{
	Name:  "data",
	Usage: "data COMMAND",
	Subcommands: []cli.Command{
		dataPush,
		dataGet,
	},
}

// debrayer le chiffrement
//taille des blocs
var dataPush = cli.Command{
	Name:      "push",
	Usage:     "push a file in the storage",
	ArgsUsage: "<file_path>",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <file_name>."))
		} else {
			filePath := c.Args().First()
			err := client.New().Data.Push(filePath, client.DefaultExecutionTimeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "data push", false).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var dataGet = cli.Command{
	Name:      "get",
	Usage:     "fetch a file in the storage",
	ArgsUsage: "<file_name>",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <file_path>."))
		} else {
			filePath := c.Args().First()
			err := client.New().Data.Get(filePath, client.DefaultExecutionTimeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "data get", false).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}
