/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

const subnetCmdLabel = "subnet"

// SubnetCommands command
var SubnetCommands = &cli.Command{
	Name:    subnetCmdLabel,
	Aliases: []string{"net"},
	Usage:   subnetCmdLabel + " COMMAND",
	Subcommands: []*cli.Command{
		subnetCreate,
		subnetDelete,
		subnetInspect,
		subnetList,
		subnetVIPCommands,
		subnetSecurityCommands,
	},
}

var subnetList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List existing Subnets (created by SafeScale)",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "network",
			//Aliases: []string{"N"},
			Value: "",
			Usage: "defines the network where to search for the subnets; default: empty, meaning all managed subnets",
		},
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Usage:   "List all Subnets on tenant (not only those created by SafeScale)",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", networkCmdLabel, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		subnets, err := clientSession.Subnet.List(c.String("network"), c.Bool("all"), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of networks", false).Error())))
		}
		return clitools.SuccessResponse(subnets)
	},
}

var subnetDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "delete SUBNETNAME",
	ArgsUsage: "SUBNETNAME [SUBNETNAME ...]",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "network",
			//Aliases: []string{"N"},
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Network_name>."))
		}

		var subnetList []string
		subnetList = append(subnetList, c.Args().Tail()...)

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.Delete(c.String("network"), subnetList, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of subnet", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var subnetInspect = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Show details of a subnet",
	ArgsUsage: "SUBNETNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "network",
			Aliases: []string{"N"},
			Value:   "",
			Usage:   "defines the Network where to search for the Subnet, when a same Subnet name is used in several Networks.",
		},
	},
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

		subnet, err := clientSession.Subnet.Inspect(c.String("network"), c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of network", false).Error())))
		}

		// Convert struct to map using struct to json then json to map
		// errors not checked willingly; json encoding and decoding of simple structs are not supposed to fail
		mapped := map[string]interface{}{}
		jsoned, _ := json.Marshal(subnet)
		_ = json.Unmarshal(jsoned, &mapped)

		// Get gateway(s) information (needs the name(s) in the output map)
		var pgw, sgw *protocol.Host
		pgwID := subnet.GetGatewayIds()[0]
		sgwID := subnet.GetGatewayIds()[1]

		// Added operation status
		opState := subnet.State
		mapped["state"] = opState.String()

		pgw, err = clientSession.Host.Inspect(pgwID, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			var what string
			if sgwID != "" {
				what = "primary "
			}
			casted := fail.Wrap(err, fmt.Sprintf("failed to inspect subnet: cannot inspect %sgateway", what))
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(casted.Error())))
		}
		mapped["gateway_name"] = pgw.Name
		if sgwID != "" {
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

var subnetCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a subnet",
	ArgsUsage: "SUBNETNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Usage: "Name or ID of the Network in which the subnet must be created",
		},
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
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, c.Command.Name, c.Args())
		if c.Args().Get(0) == "" {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETNAME."))
		}

		sizing, err := constructHostDefinitionStringFromCLI(c, "sizing")
		if err != nil {
			return err
		}
		subnetDef := protocol.SubnetCreateRequest{
			Name:     c.Args().First(),
			Cidr:     c.String("cidr"),
			Network:  &protocol.Reference{Name: c.String("network")},
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

		network, err := clientSession.Subnet.Create(&subnetDef, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of subnet", true).Error())))
		}
		return clitools.SuccessResponse(network)
	},
}

const vipCmdLabel = "vip"

// subnetVIPCommands handles 'network vip' commands
var subnetVIPCommands = &cli.Command{
	Name:      vipCmdLabel,
	Aliases:   []string{"virtualip"},
	Usage:     "manage subnet virtual IP",
	ArgsUsage: "COMMAND",

	Subcommands: []*cli.Command{
		subnetVIPCreateCommand,
		subnetVIPInspectCommand,
		subnetVIPDeleteCommand,
		subnetVIPBindCommand,
		subnetVIPUnbindCommand,
	},
}

var subnetVIPCreateCommand = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "creates a VIP in a subnet",
	ArgsUsage: "SUBNETNAME VIPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "creation of subnet VIP not yet implemented"))
	},
}

var subnetVIPInspectCommand = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Show details of a VIP of a subnet",
	ArgsUsage: "SUBNETNAME VIPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "inspection of subnet VIP not yet implemented"))

	},
}

var subnetVIPDeleteCommand = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "destroy"},
	Usage:     "delete SUBNETNAME VIPNAME",
	ArgsUsage: "SUBNETNAME VIPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "deletion of subnet VIP not yet implemented"))
	},
}

var subnetVIPBindCommand = &cli.Command{
	Name:      "bind",
	Aliases:   []string{"attach"},
	Usage:     "Attach a VIP to an host",
	ArgsUsage: "SUBNETNAME VIPNAME HOSTNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 3 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "bind host to subnet VIP not yet implemented"))
	},
}

var subnetVIPUnbindCommand = &cli.Command{
	Name:      "unbind",
	Aliases:   []string{"detach"},
	Usage:     "unbind SUBNETNAME VIPNAME HOSTNAME",
	ArgsUsage: "SUBNETNAME VIPNAME HOSTNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 3 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		// network, err := clientSession.Network.Inspect(c.Args().First(), temporal.GetExecutionTimeout()
		// if err != nil {
		// 	err = fail.FromGRPCStatus(err)
		// 	return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unbind host from network VIP", false).Error()))
		// }

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "unbind host from subnet VIP not yet implemented"))
	},
}

const securityCmdLabel = "security"

// subnetSecurityGroupCommand command
var subnetSecurityCommands = &cli.Command{
	Name:  securityCmdLabel,
	Usage: "manages security of subnets",
	Subcommands: []*cli.Command{
		subnetSecurityGroupCommands,
	},
}

const groupCmdLabel = "group"

// subnetSecurityGroupCommand command
var subnetSecurityGroupCommands = &cli.Command{
	Name:  groupCmdLabel,
	Usage: "manages security group of subnets",
	Subcommands: []*cli.Command{
		subnetSecurityGroupAddCommand,
		subnetSecurityGroupRemoveCommand,
		subnetSecurityGroupEnableCommand,
		subnetSecurityGroupListCommand,
		subnetSecurityGroupDisableCommand,
	},
}

var subnetSecurityGroupAddCommand = &cli.Command{
	Name:      "add",
	Aliases:   []string{"attach", "bind"},
	Usage:     "Add a security group to a subnet",
	ArgsUsage: "SUBNETNAME GROUPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
		&cli.BoolFlag{
			Name:  "disabled",
			Value: false,
			Usage: "adds the security group to the network without applying its rules",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.BindSecurityGroup(c.String("network"), c.Args().First(), c.Args().Get(1), c.Bool("disabled"), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "adding security group to network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var subnetSecurityGroupRemoveCommand = &cli.Command{
	Name:      "remove",
	Aliases:   []string{"rm", "detach", "unbind"},
	Usage:     "removes a security group from a subnet",
	ArgsUsage: "SUBNETNAME GROUPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.UnbindSecurityGroup(c.String("network"), c.Args().First(), c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "removing security group from network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var subnetSecurityGroupListCommand = &cli.Command{
	Name:      "list",
	Aliases:   []string{"show"},
	Usage:     "lists security groups bound to subnet",
	ArgsUsage: "SUBNETNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
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
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%v'", networkCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		var kind string
		if c.Bool("all") {
			kind = "all"
		} else {
			kind = strings.ToLower(c.String("kind"))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		resp, err := clientSession.Subnet.ListSecurityGroups(c.String("network"), c.Args().First(), kind, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "listing bound security groups of network", false).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var subnetSecurityGroupEnableCommand = &cli.Command{
	Name:      "enable",
	Aliases:   []string{"activate"},
	Usage:     "Enables a security group on a subnet",
	ArgsUsage: "SUBNETNAME GROUPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.EnableSecurityGroup(c.String("network"), c.Args().First(), c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "enabling security group on network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var subnetSecurityGroupDisableCommand = &cli.Command{
	Name:      "disable",
	Aliases:   []string{"deactivate"},
	Usage:     "disable SUBNETNAME GROUPNAME",
	ArgsUsage: "SUBNETNAME GROUPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", hostCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.DisableSecurityGroup(c.String("network"), c.Args().First(), c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "disabling bound security group on network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
