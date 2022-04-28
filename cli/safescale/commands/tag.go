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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package commands

import (
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/client"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

var tagCmdName = "tag"

// TagCommand tag command
var TagCommand = cli.Command{
	Name:  "tag",
	Usage: "tag COMMAND",
	Subcommands: cli.Commands{
		tagList,
		tagInspect,
		tagDelete,
		tagCreate,
	},
}

var tagList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available tags",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "all",
			Usage: "List all Tags on tenant",
		}},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		tags, err := clientSession.Tag.List(c.Bool("all"), temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of tags", false).Error())))
		}
		return clitools.SuccessResponse(tags.Tags)
	},
}

var tagInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Inspect tag",
	ArgsUsage: "<Tag_name|Tag_ID>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Tag_name|Tag_ID>."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		tagInfo, err := clientSession.Tag.Inspect(c.Args().First(), temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of tag", false).Error())))
		}
		return clitools.SuccessResponse(tagInfo)
	},
}

var tagDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Remove tag",
	ArgsUsage: "<Tag_name|Tag_ID> [<Tag_name|Tag_ID>...]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "force",
			Usage: "Force deletion even if the tag has resources binded",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Tag_name|Tag_ID>."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		var tagList []string
		tagList = append(tagList, c.Args().First())
		tagList = append(tagList, c.Args().Tail()...)

		err := clientSession.Tag.Delete(tagList, temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of tag", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var tagCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a tag",
	ArgsUsage: "<Tag_name>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Tag_name>. "))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		def := protocol.TagCreateRequest{
			Name: c.Args().First(),
		}

		tag, err := clientSession.Tag.Create(&def, temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of tag", true).Error())))
		}
		return clitools.SuccessResponse(tag)
	},
}
