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
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var imageCmdName = "image"

// ImageCmd command
var ImageCmd = cli.Command{
	Name:  "image",
	Usage: "image COMMAND",
	Subcommands: []cli.Command{
		imageList,
	},
}

var imageList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available images",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "List all available images in tenant (without any filter)",
		}},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", imageCmdName, c.Command.Name, c.Args())
		images, err := client.New().Image.List(c.Bool("all"), temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "list of images", false).Error())))
		}
		return clitools.SuccessResponse(images.GetImages())
	},
}
