/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"encoding/json"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/lib/client"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const publicIPCmdLabel = "public-ip"

// PublicIPCommand command
var PublicIPCommand = &cli.Command{
	Name:    publicIPCmdLabel,
	Aliases: []string{"net"},
	Usage:   publicIPCmdLabel + " COMMAND",
	Subcommands: []*cli.Command{
		publicipCreate,
		publicipDelete,
		publicipInspect,
		publicipList,
		publicipBind,
		publicipUnbind,
	},
}

var publicipList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List existing public IPs",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "all",
			Usage: "List all public IPs on tenant (not only those created by SafeScale)",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", publicIPCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		list, err := clientSession.PublicIP.List(c.Bool("all"), temporal.GetExecutionTimeout())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of public IPs", false).Error())))
		}
		return clitools.SuccessResponse(list)
	},
}

var publicipDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "delete PUBLICIP",
	ArgsUsage: "PUBLICIP [PUBLICIP ...]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "force, f",
			Usage: "If used, deletes the publicip ignoring metadata discrepancies",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", publicIPCmdLabel, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument PUBLICIP."))
		}

		force := c.Bool("force")

		var publicipList []string
		publicipList = append(publicipList, c.Args().First())
		publicipList = append(publicipList, c.Args().Tail()...)

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		if err := clientSession.PublicIP.Delete(publicipList, force, temporal.GetExecutionTimeout()); err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of publicip", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var publicipInspect = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "inspect PUBLICIP",
	ArgsUsage: "PUBLICIP",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", publicIPCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument PUBLICIP."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		publicip, err := clientSession.PublicIP.Inspect(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of publicip", false).Error())))
		}

		// Convert struct to map using struct to json then json to map
		// errors not checked willingly; json encoding and decoding of simple structs are not supposed to fail
		mapped := map[string]interface{}{}
		jsoned, _ := json.Marshal(publicip)
		_ = json.Unmarshal(jsoned, &mapped)
		return clitools.SuccessResponse(mapped)
	},
}

var publicipCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a public IP",
	ArgsUsage: "PUBLICIPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "type",
			Value: "ipv4",
			Usage: "Defines what kind of IP is wanted ('ipv4' or 'ipv6'; default='ipv4')",
		},
		&cli.StringFlag{
			Name:  "description",
			Value: "",
			Usage: "Defines a description for the created Public IP",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", publicIPCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument PUBLICIPNAME."))
		}

		castedType := ipversion.FromString(c.String("type"))
		if castedType == ipversion.UNKNOWN {
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument(fmt.Sprintf("Invalid value '%s' for flag 'type'", c.String("type"))))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		publicip, err := clientSession.PublicIP.Create(c.Args().First(), castedType, c.String("description"), temporal.GetExecutionTimeout())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of publicip", true).Error())))
		}
		return clitools.SuccessResponse(publicip)
	},
}

var publicipBind = &cli.Command{
	Name:      "bind",
	Aliases:   []string{"attach", "connect"},
	Usage:     "Binds a public IP to a host",
	ArgsUsage: "PUBLICIP HOST",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", publicIPCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments PUBLICIP and/or HOST."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		if err := clientSession.PublicIP.Bind(c.Args().First(), c.Args().Get(1), temporal.GetExecutionTimeout()); err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "binding of publicip to host", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var publicipUnbind = &cli.Command{
	Name:      "unbind",
	Aliases:   []string{"detach", "disconnect"},
	Usage:     "Unbinds a public IP from a host",
	ArgsUsage: "PUBLICIP HOST",

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", publicIPCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments PUBLICIP and/or HOST."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		if err := clientSession.PublicIP.Unbind(c.Args().First(), c.Args().Get(1), temporal.GetExecutionTimeout()); err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unbinding of publicip from host", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
