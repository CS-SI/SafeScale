/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/protocol"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const networkCmdLabel = "network"

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
		networkSecurityCommands,
		subnetCommands,
	},
}

var networkList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List existing Networks (created by SafeScale)",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "provider",
			Aliases: []string{"all", "a"},
			Usage:   "Lists all Networks available on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())

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
	Usage:     "delete NETWORKREF",
	ArgsUsage: "NETWORKREF [NETWORKREF ...]",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
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
	ArgsUsage: "NETWORKREF",
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

		if len(network.Subnets) == 1 {
			if network.Subnets[0] == network.Name {
				subnet, err := clientSession.Subnet.Inspect(network.Id, network.Name, temporal.GetExecutionTimeout())
				if err != nil {
					err = fail.FromGRPCStatus(err)
					return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of network", false).Error())))
				}

				subnetMapped := map[string]interface{}{}
				jsoned, _ := json.Marshal(subnet)
				_ = json.Unmarshal(jsoned, &subnetMapped)

				mapped["network_id"] = mapped["id"]
				mapped["network_cidr"] = mapped["cidr"]
				delete(mapped, "cidr")
				for k, v := range subnetMapped {
					mapped[k] = v
				}

				if err = queryGatewaysInformation(clientSession, subnet, mapped); err != nil {
					return err
				}

				// Remove entry 'subnets'
				delete(mapped, "subnets")
			}
		}

		return clitools.SuccessResponse(mapped)
	},
}

// Get gateway(s) information
func queryGatewaysInformation(session *client.Session, subnet *protocol.Subnet, mapped map[string]interface{}) (err error) {
	var pgw, sgw *protocol.Host
	gwIDs := subnet.GetGatewayIds()

	var gateways = make([]string, 0, len(gwIDs))
	if len(gwIDs) > 0 {
		pgw, err = session.Host.Inspect(gwIDs[0], temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			var what string
			if len(gwIDs) > 1 {
				what = "primary "
			}
			xerr := fail.Wrap(err, fmt.Sprintf("failed to inspect network: cannot inspect %sgateway", what))
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(xerr.Error())))
		}
		mapped["gateway_name"] = pgw.Name
		gateways = append(gateways, pgw.Name)
	}
	if len(gwIDs) > 1 {
		sgw, err = session.Host.Inspect(gwIDs[1], temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			xerr := fail.Wrap(err, "failed to inspect network: cannot inspect secondary gateway")
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(xerr.Error())))
		}
		mapped["secondary_gateway_name"] = sgw.Name
		gateways = append(gateways, sgw.Name)
	}
	if len(gateways) > 0 {
		mapped["gateways"] = gateways
	}

	// Remove entry 'virtual_ip' if empty
	if _, ok := mapped["virtual_ip"]; ok && len(mapped["virtual_ip"].(map[string]interface{})) == 0 {
		delete(mapped, "virtual_ip")
	}

	return nil
}

var networkCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a network",
	ArgsUsage: "NETWORKREF",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "cidr",
			Aliases: []string{"N"},
			Value:   "",
			Usage:   "CIDR of the Network (default: 192.168.0.0/23)",
		},
		&cli.BoolFlag{
			Name:    "empty",
			Aliases: []string{"no-default-subnet"},
			Value:   false,
			Usage:   "Do not create a default Subnet with the same name than the Network",
		},
		&cli.BoolFlag{
			Name:    "keep-on-failure",
			Aliases: []string{"k"},
			Usage:   "If used, the resource(s) is(are) not deleted on failure (default: not set)",
		},
		&cli.StringFlag{
			Name:  "os",
			// Value: "Ubuntu 20.04",
			Usage: "Image name for the gateway",
		},
		&cli.StringFlag{
			Name:  "gwname",
			Value: "",
			Usage: "Name for the gateway. Default to 'gw-<network_name>'",
		},
		&cli.IntFlag{
			Name:    "gwport",
			Aliases: []string{"default-ssh-port"},
			Value:   22,
			Usage: `Define the port to use for SSH (default: 22) in default subnet;
			Meaningful only if --empty is not used`,
		},
		&cli.BoolFlag{
			Name: "failover",
			Usage: `creates 2 gateways for the network with a VIP used as internal default route;
			Meaningful only if --empty is not used`,
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
			Meaningful only if --empty is not used`,
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		}

		var (
			sizing string
			err    error
		)
		if !c.Bool("empty") {
			sizing, err = constructHostDefinitionStringFromCLI(c, "sizing")
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}
		}
		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		gatewaySSHPort := uint32(c.Int("gwport"))
		network, err := clientSession.Network.Create(
			c.Args().Get(0), c.String("cidr"), c.Bool("empty"),
			c.String("gwname"), gatewaySSHPort, c.String("os"), sizing,
			c.Bool("keep-on-failure"),
			temporal.GetExecutionTimeout(),
		)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of network", true).Error())))
		}
		return clitools.SuccessResponse(network)
	},
}

// networkSecurityGroupCommand command
var networkSecurityCommands = &cli.Command{
	Name:  securityCmdLabel,
	Usage: "manages security of networks",
	Subcommands: []*cli.Command{
		networkSecurityGroupCommands,
	},
}

// networkSecurityGroupCommand command
var networkSecurityGroupCommands = &cli.Command{
	Name:    groupCmdLabel,
	Aliases: []string{"sg"},
	Usage:   groupCmdLabel + " COMMAND",
	Subcommands: []*cli.Command{
		networkSecurityGroupList,
		networkSecurityGroupCreate,
		networkSecurityGroupDelete,
		networkSecurityGroupInspect,
		networkSecurityGroupClear,
		networkSecurityGroupBonds,
		networkSecurityGroupRuleCommand,
	},
}

var networkSecurityGroupList = &cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "List available Security Groups (created by SafeScale)",
	ArgsUsage: "[NETWORKREF]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Usage:   "List all Security Groups on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		// networkRef := c.Args().First()

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
			var resp []interface{}
			for _, v := range list.SecurityGroups {
				item, xerr := reformatSecurityGroup(v, false)
				if xerr != nil {
					return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(xerr.Error())))
				}
				resp = append(resp, item)
			}
			return clitools.SuccessResponse(resp)
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkSecurityGroupInspect = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Shows details of Security Group",
	ArgsUsage: "NETWORKREF GROUPREF",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		resp, err := clientSession.SecurityGroup.Inspect(c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		formatted, err := reformatSecurityGroup(resp, false)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		return clitools.SuccessResponse(formatted)
	},
}

func reformatSecurityGroup(in *protocol.SecurityGroupResponse, showRules bool) (map[string]interface{}, error) {
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	jsoned, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	out := map[string]interface{}{}
	err = json.Unmarshal(jsoned, &out)
	if err != nil {
		return nil, err
	}

	switch showRules {
	case false:
		delete(out, "rules")
	case true:
		if rules, ok := out["rules"].([]interface{}); ok {
			for _, v := range rules {
				item := v.(map[string]interface{})
				direction := item["direction"].(float64)
				etherType := item["ether_type"].(float64)
				item["direction_label"] = strings.ToLower(securitygroupruledirection.Enum(direction).String())
				item["ether_type_label"] = strings.ToLower(ipversion.Enum(etherType).String())
			}
		} else {
			out["rules"] = nil
		}
	}

	return out, nil
}

var networkSecurityGroupCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a new Security Group",
	ArgsUsage: "NETWORKREF GROUPREF",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "description",
			Aliases: []string{"comment,d"},
			Usage:   "Describe the group",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		req := abstract.SecurityGroup{
			Name:        c.Args().Get(1),
			Description: c.String("description"),
		}
		resp, err := clientSession.SecurityGroup.Create(c.Args().First(), req, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of security-group", true).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

// networkSecurityGroupClear ...
var networkSecurityGroupClear = &cli.Command{
	Name:      "clear",
	Aliases:   []string{"reset"},
	Usage:     "deletes all rules of a Security Group",
	ArgsUsage: "NETWORKREF GROUPREF",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.SecurityGroup.Clear(c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "reset of a security-group", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkSecurityGroupDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Remove Security Group",
	ArgsUsage: "NETWORKREF GROUPREF [GROUPREF ...]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "force",
			Usage: "Force deletion, removing from hosts and networks if needed",
			Value: false,
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%v'", networkCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.SecurityGroup.Delete(c.Args().Tail(), c.Bool("force"), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of security-group", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkSecurityGroupBonds = &cli.Command{
	Name:      "bonds",
	Aliases:   []string{"links", "attachments"},
	Usage:     "List resources Security Group is bound to",
	ArgsUsage: "NETWORKREF GROUPREF",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "kind",
			Value: "all",
			Usage: "Narrow to the kind of resource specified; can be 'hosts', 'subnets' or 'all' (default: 'all')",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		kind := strings.ToLower(c.String("kind"))

		list, err := clientSession.SecurityGroup.Bonds(c.Args().Get(1), kind, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of Security Groups", false).Error())))
		}
		result := map[string]interface{}{}
		if len(list.Hosts) > 0 {
			hosts := make([]map[string]interface{}, len(list.Hosts))
			jsoned, _ := json.Marshal(list.Hosts)
			err = json.Unmarshal(jsoned, &hosts)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "list of security-groups", false).Error())))
			}
			result["hosts"] = hosts
		}
		if len(list.Subnets) > 0 {
			networks := make([]map[string]interface{}, len(list.Subnets))
			jsoned, _ := json.Marshal(list.Subnets)
			err = json.Unmarshal(jsoned, &networks)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "list of security-groups", false).Error())))
			}
			result["networks"] = networks
		}
		if len(result) > 0 {
			return clitools.SuccessResponse(result)
		}
		return clitools.SuccessResponse(nil)
	},
}

const ruleCmdLabel = "rule"

// networkSecurityGroupRuleCommand command
var networkSecurityGroupRuleCommand = &cli.Command{
	Name:      ruleCmdLabel,
	Usage:     "manages rules in Security Groups of Networks",
	ArgsUsage: "NETWORKREF|- GROUPREF",
	Subcommands: []*cli.Command{
		networkSecurityGroupRuleAdd,
		networkSecurityGroupRuleDelete,
	},
}

// networkSecurityGroupRuleAdd ...
// NETWORKREF is not really used (Security Group Name are unique across the tenant by design), but kept for command consistency
var networkSecurityGroupRuleAdd = &cli.Command{
	Name:      "add",
	Aliases:   []string{"new"},
	Usage:     "add a new rule to a Security Group",
	ArgsUsage: "NETWORKREF|- GROUPREF",
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
		&cli.StringSliceFlag{
			Name:  "cidr",
			Usage: "source/target of the rule; may be used multiple times",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
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

		rule := abstract.SecurityGroupRule{
			Description: c.String("description"),
			EtherType:   etherType,
			Direction:   direction,
			Protocol:    c.String("protocol"),
			PortFrom:    int32(c.Int("port-from")),
			PortTo:      int32(c.Int("port-to")),
			Targets:     c.StringSlice("cidr"),
		}

		if err := clientSession.SecurityGroup.AddRule(c.Args().Get(1), rule, temporal.GetExecutionTimeout()); err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "addition of a rule to a security-group", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

// networkSecurityGroupRuleDelete ...
// NETWORKREF is not really used (Security Group Name are unique across the tenant by design), but kept for command consistency
var networkSecurityGroupRuleDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove", "destroy"},
	Usage:     "delete a rule from a Security Group",
	ArgsUsage: "NETWORKREF|- GROUPREF",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name: "direction",
			// Aliases: []string{"D"},
			Value: "",
			Usage: "ingress or egress",
		},
		&cli.StringFlag{
			Name:  "protocol",
			Value: "tcp",
			Usage: "Protocol",
		},
		&cli.StringFlag{
			Name: "type",
			// Aliases: []string{"T"},
			Value: "ipv4",
			Usage: "ipv4 or ipv6",
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
		&cli.StringSliceFlag{
			Name:  "cidr",
			Usage: "source/target of the rule",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
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

		rule := abstract.SecurityGroupRule{
			EtherType: etherType,
			Direction: direction,
			Protocol:  c.String("protocol"),
			PortFrom:  int32(c.Int("port-from")),
			PortTo:    int32(c.Int("port-to")),
			Targets:   c.StringSlice("cidr"),
		}
		err := clientSession.SecurityGroup.DeleteRule(c.Args().Get(1), rule, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of a rule from a security-group", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

const subnetCmdLabel = "subnet"

// SubnetCommands command
var subnetCommands = &cli.Command{
	Name:  subnetCmdLabel,
	Usage: "manages Subnets of Networks",
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
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "List existing Subnets (created by SafeScale)",
	ArgsUsage: "NETWORKREF",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Usage:   "List all Subnets on tenant (not only those created by SafeScale)",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args %q", networkCmdLabel, subnetCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		resp, err := clientSession.Subnet.List(networkRef, c.Bool("all"), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of subnets", false).Error())))
		}
		var result []map[string]interface{}
		subnets := resp.GetSubnets()
		if len(subnets) > 0 {
			jsoned, err := json.Marshal(subnets)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of subnets", false).Error())))
			}
			if err != json.Unmarshal(jsoned, &result) {
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of subnets", false).Error())))
			}
			for _, v := range result {
				delete(v, "gateway_ids")
				delete(v, "state")
			}
		}
		return clitools.SuccessResponse(result)
	},
}

var subnetDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "delete SUBNETREF",
	ArgsUsage: "NETWORKREF SUBNETREF [SUBNETREF ...]",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		var list []string
		list = append(list, c.Args().Tail()...)

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.Delete(networkRef, list, temporal.GetExecutionTimeout())
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
	ArgsUsage: "NETWORKREF SUBNETREF",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		subnet, err := clientSession.Subnet.Inspect(networkRef, c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of subnet", false).Error())))
		}

		// Convert struct to map using struct to json then json to map
		// errors not checked willingly; json encoding and decoding of simple structs are not supposed to fail
		mapped := map[string]interface{}{}
		jsoned, _ := json.Marshal(subnet)
		_ = json.Unmarshal(jsoned, &mapped)

		if err = queryGatewaysInformation(clientSession, subnet, mapped); err != nil {
			return err
		}
		return clitools.SuccessResponse(mapped)
	},
}

var subnetCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a subnet",
	ArgsUsage: "NETWORKREF SUBNETREF",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "cidr",
			Aliases: []string{"N"},
			Value:   "",
			Usage:   "cidr of the network",
		},
		&cli.StringFlag{
			Name:  "os",
			// Value: "Ubuntu 20.04",
			Usage: "Image name for the gateway",
		},
		&cli.StringFlag{
			Name:  "gwname",
			Value: "",
			Usage: "Name for the gateway. Default to 'gw-<network_name>'",
		},
		&cli.IntFlag{
			Name:  "gwport",
			Value: 22,
			Usage: "port to use for SSH on the gateway",
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

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		sizing, err := constructHostDefinitionStringFromCLI(c, "sizing")
		if err != nil {
			return err
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		network, err := clientSession.Subnet.Create(
			networkRef, c.Args().Get(1), c.String("cidr"), c.Bool("failover"),
			c.String("gwname"), uint32(c.Int("gwport")), c.String("os"), sizing,
			c.Bool("keep-on-failure"),
			temporal.GetExecutionTimeout(),
		)
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
	Name:    "create",
	Aliases: []string{"new"},
	Usage: `creates a VIP in a Subnet of a Network.
		If NETWORKREF == -, SUBNETREF must be a Subnet ID`,
	ArgsUsage: "NETWORKREF|- SUBNETREF VIPNAME",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		case 2:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
		}

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "creation of subnet VIP not yet implemented"))
	},
}

var subnetVIPInspectCommand = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Show details of a VIP of a Subnet in a Network",
	ArgsUsage: "NETWORKREF|- SUBNETREF VIPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		case 2:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
		}

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "inspection of subnet VIP not yet implemented"))

	},
}

var subnetVIPDeleteCommand = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "destroy"},
	Usage:     "Deletes a VIP from a Subnet in a Network",
	ArgsUsage: "NETWORKREF|- SUBNETREF VIPNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		case 2:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
		}

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "deletion of subnet VIP not yet implemented"))
	},
}

var subnetVIPBindCommand = &cli.Command{
	Name:      "bind",
	Aliases:   []string{"attach"},
	Usage:     "Attach a VIP to an host",
	ArgsUsage: "NETWORKREF SUBNETREF VIPNAME HOSTNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		case 2:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
		case 3:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument HOSTNAME."))
		}

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "bind host to subnet VIP not yet implemented"))
	},
}

var subnetVIPUnbindCommand = &cli.Command{
	Name:      "unbind",
	Aliases:   []string{"detach"},
	Usage:     "unbind NETWORKREF SUBNETREF VIPNAME HOSTNAME",
	ArgsUsage: "NETWORKREF SUBNETREF VIPNAME HOSTNAME",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "network",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		case 2:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
		case 3:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument HOSTNAME."))
		}

		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.NotImplemented, "unbind host from subnet VIP not yet implemented"))
	},
}

const securityCmdLabel = "security"

// subnetSecurityGroupCommand command
var subnetSecurityCommands = &cli.Command{
	Name:      securityCmdLabel,
	Usage:     "manages security of subnets",
	ArgsUsage: "NETWORKREF|- SUBNETREF GROUPREF",
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
	ArgsUsage: "NETWORKREF|- SUBNETREF GROUPREF",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "disabled",
			Value: false,
			Usage: "adds the security group to the network without applying its rules",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		case 2:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.BindSecurityGroup(networkRef, c.Args().Get(1), c.Args().Get(2), c.Bool("disabled"), temporal.GetExecutionTimeout())
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
	ArgsUsage: "NETWORKREF SUBNETREF GROUPREF",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		case 2:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.UnbindSecurityGroup(networkRef, c.Args().Get(1), c.Args().Get(2), temporal.GetExecutionTimeout())
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
	ArgsUsage: "NETWORKREF SUBNETREF",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"a"},
			Value:   true,
			Usage:   "List all security groups no matter what is the status (enabled or disabled)",
		},
		&cli.StringFlag{
			Name:  "state",
			Value: "all",
			Usage: "Narrows to the security groups in defined state; can be 'enabled', 'disabled' or 'all' (default: 'all')",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%v'", networkCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		var state string
		if c.Bool("all") {
			state = "all"
		} else {
			state = c.String("state")
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		list, err := clientSession.Subnet.ListSecurityGroups(networkRef, c.Args().Get(1), state, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "listing bound security groups of subnet", false).Error())))
		}
		return clitools.SuccessResponse(list.Subnets)
	},
}

var subnetSecurityGroupEnableCommand = &cli.Command{
	Name:      "enable",
	Aliases:   []string{"activate"},
	Usage:     "Enables a security group on a subnet",
	ArgsUsage: "NETWORKREF SUBNETREF GROUPREF",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		case 2:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.EnableSecurityGroup(networkRef, c.Args().Get(1), c.Args().Get(2), temporal.GetExecutionTimeout())
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
	Usage:     "disable SUBNETREF GROUPREF",
	ArgsUsage: "NETWORKREF SUBNETREF GROUPREF",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", hostCmdLabel, subnetCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
		case 2:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		err := clientSession.Subnet.DisableSecurityGroup(networkRef, c.Args().Get(1), c.Args().Get(2), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "disabling bound security group on network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
