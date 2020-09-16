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

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var securityGroupCmdLabel = "security-group"

// SecurityGroupCommand command
var SecurityGroupCommand = &cli.Command{
	Name:    securityGroupCmdLabel,
	Aliases: []string{"sg"},
	Usage:   securityGroupCmdLabel + " COMMAND",
	Subcommands: []*cli.Command{
		securityGroupList,
		securityGroupCreate,
		securityGroupDelete,
		securityGroupInspect,
		securityGroupRuleCommand,
	},
}

var securityGroupList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available Security Groups (created by SafeScale)",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Usage:   "List all Security Groups on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s '%s' with args '%s'", securityGroupCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		list, err := clientSession.SecurityGroup.List(c.Bool("all"), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of Security Groups", false).Error())))
		}
		if len(list.SecurityGroups) > 0 {
			jsoned, _ := json.Marshal(list.SecurityGroups)
			var result []interface{}
			err = json.Unmarshal([]byte(jsoned), &result)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "list of security-groups", false).Error())))
			}
			return clitools.SuccessResponse(result)
		}
		return clitools.SuccessResponse(nil)
	},
}

var securityGroupInspect = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "inspect GROUPNAME",
	ArgsUsage: "GROUPNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPNAME."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		resp, err := clientSession.SecurityGroup.Inspect(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(resp)
	},
}

var securityGroupCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a new Security Group",
	ArgsUsage: "GROUPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "description",
			Aliases: []string{"comment,d"},
			Usage:   "Describe the group",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPNAME."))
		}
		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		req := protocol.SecurityGroupRequest{
			Name:        c.Args().First(),
			Description: c.String("description"),
		}
		resp, err := clientSession.SecurityGroup.Create(&req, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of security-group", true).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var securityGroupClear = &cli.Command{
	Name:      "clear",
	Aliases:   []string{"reset"},
	Usage:     "deletes all rules of a Security Group",
	ArgsUsage: "GROUPNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPNAME."))
		}
		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.SecurityGroup.Clear(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "reset of a security-group", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var securityGroupDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Delete Security Group",
	ArgsUsage: "GROUPNAME [GROUPNAME ...]",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPNAME."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		var sgList []string
		sgList = append(sgList, c.Args().First())
		sgList = append(sgList, c.Args().Tail()...)

		err := clientSession.SecurityGroup.Delete(sgList, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of security-group", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

// securityGroupRuleCommand command
var securityGroupRuleCommand = &cli.Command{
	Name:    "rule",
	Aliases: []string{"sg"},
	Usage:   "rule COMMAND",
	Subcommands: []*cli.Command{
		securityGroupRuleAdd,
		securityGroupRuleDelete,
	},
}

var securityGroupRuleAdd = &cli.Command{
	Name:      "add",
	Aliases:   []string{"new"},
	Usage:     "add a new rule to a Security Group",
	ArgsUsage: "GROUPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "description",
			Value: "",
		},
		&cli.StringFlag{
			Name:    "direction",
			Aliases: []string{"D"},
			Value:   "",
			Usage:   "ingress or egress",
		},
		&cli.StringFlag{
			Name:  "protocol",
			Value: "tcp",
			Usage: "Protocol",
		},
		&cli.StringFlag{
			Name:    "type",
			Aliases: []string{"T"},
			Value:   "ipv4",
			Usage:   "ipv4 or ipv6",
		},
		&cli.IntFlag{
			Name:  "port-from",
			Value: 0,
			Usage: "first port of the rule",
		},
		&cli.IntFlag{
			Name:  "port-to",
			Value: 0,
			Usage: "last port of the rule",
		},
		&cli.StringFlag{
			Name:  "cidr",
			Usage: "source/target of the rule",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPNAME."))
		}

		etherType, xerr := ipversion.Parse(c.String("type"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidOption, xerr.Error()))
		}

		direction, xerr := securitygroupruledirection.Parse(c.String("direction"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidOption, xerr.Error()))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		req := protocol.SecurityGroupRuleRequest{
			Group: &protocol.Reference{
				TenantId: "", // FUTURE: to be set to tenant to use
				Name:     c.Args().First(),
			},
			Rule: &protocol.SecurityGroupRule{
				Description: c.String("description"),
				EtherType:   protocol.SecurityGroupRuleEtherType(etherType),
				Direction:   protocol.SecurityGroupRuleDirection(direction),
				Protocol:    c.String("protocol"),
				PortFrom:    uint32(c.Int("port-from")),
				PortTo:      uint32(c.Int("port-to")),
				Cidr:        c.String("cidr"),
			},
		}

		err := clientSession.SecurityGroup.AddRule(&req, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "addition of a rule to a security-group", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var securityGroupRuleDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove", "destroy"},
	Usage:     "delete a rule identified by id from a Security Group",
	ArgsUsage: "GROUPNAME RULEID",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPNAME."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.SecurityGroup.DeleteRule(c.Args().First(), c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of a rule from a security-group", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
