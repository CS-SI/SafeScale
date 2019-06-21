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

package commands

import (
	"strings"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
)

// DataCmd command
var DataCmd = cli.Command{
	Name:  "data",
	Usage: "data COMMAND",
	Subcommands: []cli.Command{
		dataPush,
		dataGet,
		dataList,
		dataDelete,
	},
}

// debrayer le chiffrement
//taille des blocs
var dataPush = cli.Command{
	Name:      "push",
	Usage:     "push a file in the storage",
	ArgsUsage: "<local_file_path>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "file-name, f",
			Usage: "File name on the object storage",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <local_file_path>."))
		}

		localFilePath := utils.AbsPathify(c.Args().First())
		var fileName string
		if c.String("file-name") != "" {
			fileName = c.String("file-name")
		} else {
			fileName = strings.Split(localFilePath, "/")[len(strings.Split(localFilePath, "/"))-1]
		}
		err := client.New().Data.Push(localFilePath, fileName, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "data push", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var dataGet = cli.Command{
	Name:      "get",
	Usage:     "fetch a file in the storage",
	ArgsUsage: "<file_name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "storage-path, s",
			Usage: "file where the datas will be stored",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <file_name>."))
		}

		fileName := c.Args().First()
		var localFilePath string
		if c.String("storage-path") != "" {
			localFilePath = utils.AbsPathify(c.String("storage-path"))
		} else {
			localFilePath = utils.AbsPathify(fileName)
		}

		err := client.New().Data.Get(localFilePath, fileName, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "data get", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
var dataDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"del", "rm"},
	Usage:     "delete a file of the storage",
	ArgsUsage: "<file_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <file_name>."))
		}

		fileName := c.Args().First()
		err := client.New().Data.Delete(fileName, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "data delete", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
var dataList = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "list all files in the storage",
	ArgsUsage: "<local_file_path>",
	Action: func(c *cli.Context) error {
		filesList, err := client.New().Data.List(client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "data list", false).Error())))
		}
		return clitools.SuccessResponse(filesList)
	},
}
