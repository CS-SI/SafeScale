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
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/client"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

var (
	labelCmdName = "label"
	tagCmdName   = "tag"
)

// LabelCommand tag command
var LabelCommand = cli.Command{
	Name:  labelCmdName,
	Usage: labelCmdName + " COMMAND",
	Subcommands: cli.Commands{
		labelListCommand,
		labelInspectCommand,
		labelDeleteCommand,
		labelCreateCommand,
	},
}

var labelListCommand = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available Labels",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", labelCmdName, c.Command.Name, c.Args())

		list, err := ClientSession.Label.List(false, temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of Labels", false).Error())))
		}

		var output []map[string]interface{}
		jsoned, xerr := json.Marshal(list.Labels)
		if xerr == nil {
			xerr = json.Unmarshal(jsoned, &output)
		}
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(xerr.Error())))
		}

		for _, v := range output {
			delete(v, "has_default")
		}
		return clitools.SuccessResponse(output)
	},
}

var labelInspectCommand = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Inspect Label",
	ArgsUsage: "LABELREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", labelCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument LABELREF."))
		}

		labelInfo, err := ClientSession.Label.Inspect(c.Args().First(), false, temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of Label", false).Error())))
		}

		output := map[string]interface{}{
			"id":            labelInfo.Id,
			"name":          labelInfo.Name,
			"default_value": labelInfo.DefaultValue,
			"hosts":         make([]interface{}, 0),
		}
		for _, v := range labelInfo.Hosts {
			item := map[string]string{
				"id":    v.Host.Id,
				"name":  v.Host.Name,
				"value": v.Value,
			}
			output["hosts"] = append(output["hosts"].([]interface{}), item)
		}
		return clitools.SuccessResponse(output)
	},
}

var labelDeleteCommand = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Remove Label",
	ArgsUsage: "LABELREF [LABELREF...]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "force",
			Usage: "Force deletion even if the Label has resources bound to it",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", labelCmdName, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument LABELREF."))
		}

		var list []string
		list = append(list, c.Args().First())
		list = append(list, c.Args().Tail()...)

		err := ClientSession.Label.Delete(list, false, temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of Label", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var labelCreateCommand = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a Label",
	ArgsUsage: "LABELNAME [DEFAULTVALUE]",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "value",
			Usage: "defines the default value of the Label",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", labelCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Tag_name>. "))
		}

		label, err := ClientSession.Label.Create(c.Args().First(), true, c.String("value"), temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of Label", true).Error())))
		}
		return clitools.SuccessResponse(label)
	},
}

// TagCommand tag command
var TagCommand = cli.Command{
	Name:  "tag",
	Usage: "tag COMMAND",
	Subcommands: cli.Commands{
		tagListCommand,
		tagInspectCommand,
		tagDeleteCommand,
		tagCreateCommand,
	},
}

var tagListCommand = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available Tags in Tenant",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Command.Name, c.Args())

		list, err := ClientSession.Label.List(true, temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of Tags", false).Error())))
		}

		// Remove hosts from list content for this command
		jsoned, err := json.Marshal(list.Labels)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "list of hosts", false).Error())))
		}

		var body []map[string]interface{}
		err = json.Unmarshal(jsoned, &body)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "list of hosts", false).Error())))
		}

		for _, v := range body {
			delete(v, "hosts")
		}
		return clitools.SuccessResponse(body)
	},
}

var tagInspectCommand = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Inspect tag",
	ArgsUsage: "TAGREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument TAGREF."))
		}

		tagInfo, err := ClientSession.Label.Inspect(c.Args().First(), true, temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of Tag", false).Error())))
		}

		if tagInfo.HasDefault {
			return clitools.FailureResponse(clitools.ExitOnRPC(fmt.Sprintf("inspection of Tag: '%s' is a Label", c.Args().First())))
		}

		output := map[string]interface{}{
			"id":    tagInfo.Id,
			"name":  tagInfo.Name,
			"hosts": make([]interface{}, 0),
		}
		for _, v := range tagInfo.Hosts {
			item := map[string]string{
				"id":   v.Host.Id,
				"name": v.Host.Name,
			}
			output["hosts"] = append(output["hosts"].([]interface{}), item)
		}
		return clitools.SuccessResponse(output)
	},
}

var tagDeleteCommand = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Remove tag",
	ArgsUsage: "TAGREF [TAGREF...]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "force",
			Usage: "Force deletion even if the tag has resources bound",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument TAGREF."))
		}

		var list []string
		list = append(list, c.Args().First())
		list = append(list, c.Args().Tail()...)

		err := ClientSession.Label.Delete(list, true, temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of Tag", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var tagCreateCommand = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a tag",
	ArgsUsage: "TAGNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument TAGNAME."))
		}

		tag, err := ClientSession.Label.Create(c.Args().First(), false, "", temporal.ExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of Tag", true).Error())))
		}

		return clitools.SuccessResponse(tag)
	},
}
