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
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/protocol"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var networkCmdLabel = "network"

// NetworkCommand command
var NetworkCommand = &cli.Command{
	Name:    "network",
	Aliases: []string{"net"},
	Usage:   "network COMMAND",
	Subcommands: []*cli.Command{
		networkCreate,
		networkDelete,
		networkInspect,
		networkList,
		networkVIPCommands,
		networkSecurityGroupCommands,
	},
}

var networkList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List existing Networks (created by SafeScale)",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Usage:   "ErrorList all Networks on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", networkCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		networks, err := clientSession.Network.List(c.Bool("all"), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of networks", false).Error())))
		}
		return clitools.SuccessResponse(networks.GetNetworks())
	},
}

var networkDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "delete NETWORKNAME",
	ArgsUsage: "NETWORKNAME [NETWORKNAME ...]",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Network_name>."))
		}

		var networkList []string
		networkList = append(networkList, c.Args().First())
		networkList = append(networkList, c.Args().Tail()...)

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Network.Delete(networkList, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkInspect = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Show details of a network",
	ArgsUsage: "NETWORKNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <network_name>."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of network", false).Error())))
		}

		// Convert struct to map using struct to json then json to map
		// errors not checked willingly; json encoding and decoding of simple structs are not supposed to fail
		mapped := map[string]interface{}{}
		jsoned, _ := json.Marshal(network)
		_ = json.Unmarshal(jsoned, &mapped)

		// Get gateway(s) information (needs the name(s) in the output map)
		var pgw, sgw *protocol.Host
		pgwID := network.GetGatewayId()
		sgwID := network.GetSecondaryGatewayId()

		// Added operation status
		opState := network.State
		mapped["state"] = opState.String()

		pgw, err = clientSession.Host.Inspect(pgwID, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			var what string
			if network.GetSecondaryGatewayId() != "" {
				what = "primary "
			}
			casted := fail.Wrap(err, fmt.Sprintf("failed to inspect network: cannot inspect %sgateway", what))
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(casted.Error())))
		}
		mapped["gateway_name"] = pgw.Name
		if network.GetSecondaryGatewayId() != "" {
			sgw, err = clientSession.Host.Inspect(sgwID, temporal.GetExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				casted := fail.Wrap(err, "failed to inspect network: cannot inspect secondary gateway")
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(casted.Error())))
			}
			mapped["secondary_gateway_name"] = sgw.Name
		}
		// Removed entry 'virtual_ip' if empty
		if _, ok := mapped["virtual_ip"]; ok && len(mapped["virtual_ip"].(map[string]interface{})) == 0 {
			delete(mapped, "virtual_ip")
		}

		return clitools.SuccessResponse(mapped)
	},
}

var networkCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a network",
	ArgsUsage: "NETWORKNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "cidr",
			Aliases: []string{"N"},
			Value:   "",
			Usage:   "cidr of the network",
		},
		&cli.StringFlag{
			Name:  "os",
			Value: "Ubuntu 18.04",
			Usage: "Image name for the gateway",
		},
		&cli.StringFlag{
			Name:  "gwname",
			Value: "",
			Usage: "Name for the gateway. Default to 'gw-<network_name>'",
		},
		&cli.BoolFlag{
			Name:  "failover",
			Usage: "creates 2 gateways for the network with a VIP used as internal default route",
		},
		&cli.BoolFlag{
			Name:    "keep-on-failure",
			Aliases: []string{"k"},
			Usage:   "If used, the resource(s) is(are) not deleted on failure (default: not set)",
		},
		&cli.StringFlag{
			Name:    "sizing",
			Aliases: []string{"S"},
			Usage: `Describe sizing of network gateway in format "<component><operator><value>[,...]" where:
			<component> can be cpu, cpufreq, gpu, ram, disk
			<operator> can be =,~,<=,>= (except for disk where valid operators are only = or >=):
				- = means exactly <value>
				- ~ means between <value> and 2*<value>
				- < means strictly lower than <value>
				- <= means lower or equal to <value>
				- > means strictly greater than <value>
				- >= means greater or equal to <value>
			<value> can be an integer (for cpu and disk) or a float (for ram) or an including interval "[<lower value>-<upper value>]:"
				- <cpu> is expecting an int as number of cpu cores, or an interval with minimum and maximum number of cpu cores
				- <cpufreq> is expecting an int as minimum cpu frequency in MHz
				- <gpu> is expecting an int as number of GPU (scanner would have been run first to be able to determine which template proposes GPU)
				- <ram> is expecting a float as memory size in GB, or an interval with minimum and maximum mmory size
				- <disk> is expecting an int as system disk size in GB
			examples:
				--sizing "cpu <= 4, ram <= 10, disk >= 100"
				--sizing "cpu ~ 4, ram = [14-32]" (is identical to --sizing "cpu=[4-8], ram=[14-32]")
				--sizing "cpu <= 8, ram ~ 16"
`,
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())
		if c.Args().Get(0) == "" {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <network_name>."))
		}

		sizing, err := constructHostDefinitionStringFromCLI(c, "sizing")
		if err != nil {
			return err
		}
		netdef := protocol.NetworkDefinition{
			Cidr:     c.String("cidr"),
			Name:     c.Args().Get(0),
			FailOver: c.Bool("failover"),
			Gateway: &protocol.GatewayDefinition{
				ImageId:        c.String("os"),
				Name:           c.String("gwname"),
				SizingAsString: sizing,
			},
			KeepOnFailure: c.Bool("keep-on-failure"),
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		network, err := clientSession.Network.Create(&netdef, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of network", true).Error())))
		}
		return clitools.SuccessResponse(network)
	},
}

// networkVIPCommands handles 'network vip' commands
var networkVIPCommands = &cli.Command{
	Name:      "vip",
	Aliases:   []string{"virtualip"},
	Usage:     "manage network virtual IP",
	ArgsUsage: "COMMAND",

	Subcommands: []*cli.Command{
		networkVIPCreateCommand,
		networkVIPInspectCommand,
		networkVIPDeleteCommand,
		networkVIPBindCommand,
		networkVIPUnbindCommand,
	},
}

var networkVIPCreateCommand = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create NETWORK VIPNAME",
	ArgsUsage: "<network_name> <vip_name>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s vip %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "creation of network VIP not yet implemented"))

	},
}

var networkVIPInspectCommand = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Show details of a VIP of the network",
	ArgsUsage: "NETWORKNAME VIPNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s vip %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "inspection of network VIP not yet implemented"))

	},
}

var networkVIPDeleteCommand = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "destroy"},
	Usage:     "delete NETWORKNAME VIPNAME",
	ArgsUsage: "NETWORKNAME VIPNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s vip %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <network_name>."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "deletion of network VIP not yet implemented"))
	},
}

var networkVIPBindCommand = &cli.Command{
	Name:      "bind",
	Aliases:   []string{"attach"},
	Usage:     "Attach a VIP to an host",
	ArgsUsage: "NETWORKNAME VIPNAME HOSTNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s vip %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 3 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "bind host to network VIP not yet implemented"))
	},
}

var networkVIPUnbindCommand = &cli.Command{
	Name:      "unbind",
	Aliases:   []string{"detach"},
	Usage:     "unbind NETWORKNAME VIPNAME HOSTNAME",
	ArgsUsage: "NETWORKNAME VIPNAME HOSTNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s vip %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 3 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unbind host from network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "unbind host from network VIP not yet implemented"))
	},
}

// networkSecurityGroupCommand command
var networkSecurityGroupCommands = &cli.Command{
	Name:  securityGroupCmdLabel,
	Usage: "network COMMAND",
	Subcommands: []*cli.Command{
		networkSecurityGroupAddCommand,
		networkSecurityGroupRemoveCommand,
		networkSecurityGroupEnableCommand,
		networkSecurityGroupListCommand,
		networkSecurityGroupDisableCommand,
	},
}

var networkSecurityGroupAddCommand = &cli.Command{
	Name:      "add",
	Aliases:   []string{"attach", "bind"},
	Usage:     "add NETWORKNAME GROUPNAME",
	ArgsUsage: "NETWORKNAME GROUPNAME",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "disabled",
			Value: false,
			Usage: "adds the security group to the network without applying its rules",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Network.BindSecurityGroup(c.Args().First(), c.Args().Get(1), c.Bool("disabled"), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "adding security group to network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkSecurityGroupRemoveCommand = &cli.Command{
	Name:      "remove",
	Aliases:   []string{"rm", "detach", "unbind"},
	Usage:     "remove NETWORKNAME GROUPNAME",
	ArgsUsage: "NETWORKNAME GROUPNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Network.UnbindSecurityGroup(c.Args().First(), c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "removing security group from network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkSecurityGroupListCommand = &cli.Command{
	Name:      "list",
	Aliases:   []string{"show"},
	Usage:     "list HOSTNAME",
	ArgsUsage: "HOSTNAME",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Value:   true,
			Usage:   "List all security groups no matter what is the status (enabled or disabled)",
		},
		&cli.StringFlag{
			Name:  "kind",
			Value: "all",
			Usage: "Narrows to the security groups in defined state; can be 'enabled', 'disabled' or 'all' (default: 'all')",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		kind := strings.ToLower(c.String("kind"))
		if c.Bool("all") {
			kind = "all"
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		resp, err := clientSession.Network.ListSecurityGroups(c.Args().First(), kind, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "listing bound security groups of network", false).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var networkSecurityGroupEnableCommand = &cli.Command{
	Name:      "enable",
	Aliases:   []string{"activate"},
	Usage:     "enable NETWORKNAME GROUPNAME",
	ArgsUsage: "NETWORKNAME GROUPNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Network.EnableSecurityGroup(c.Args().First(), c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "enabling security group on network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkSecurityGroupDisableCommand = &cli.Command{
	Name:      "disable",
	Aliases:   []string{"deactivate"},
	Usage:     "disable NETWORKNAME GROUPNAME",
	ArgsUsage: "NETWORKNAME GROUPNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, securityGroupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Network.DisableSecurityGroup(c.Args().First(), c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "disabling bound security group on network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
