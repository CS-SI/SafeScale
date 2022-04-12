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
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v21/lib/client"
	clitools "github.com/CS-SI/SafeScale/v21/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/strprocess"
)

var imageCmdName = "image"

// ImageCommand command
var ImageCommand = cli.Command{
	Name:  "image",
	Usage: "image COMMAND",
	Subcommands: cli.Commands{
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
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", imageCmdName, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		images, err := clientSession.Image.List(c.Bool("all"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of images", false).Error())))
		}
		return clitools.SuccessResponse(images.GetImages())
	},
}
