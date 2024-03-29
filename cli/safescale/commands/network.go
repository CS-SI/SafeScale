/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"os"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/client"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

const networkCmdLabel = "network"

// NetworkCommand command
var NetworkCommand = cli.Command{
	Name:    "network",
	Aliases: []string{"net"},
	Usage:   "network COMMAND",
	Subcommands: cli.Commands{
		networkCreate,
		networkDelete,
		networkInspect,
		networkList,
		networkSecurityCommands,
		subnetCommands,
	},
}

var networkList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List existing Networks (created by SafeScale)",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "provider, all, a",
			Usage: "Lists all Networks available on tenant (not only those created by SafeScale)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Listing networks"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		networks, err := ClientSession.Network.List(c.Bool("all"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of networks", false).Error())))
		}
		return clitools.SuccessResponse(networks.GetNetworks())
	},
}

var networkDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "delete NETWORKREF",
	ArgsUsage: "NETWORKREF [NETWORKREF ...]",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "If set, force node deletion no matter what (ie. metadata inconsistency)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		}

		var networkList []string
		networkList = append(networkList, c.Args().First())
		networkList = append(networkList, c.Args().Tail()...)

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Deleting networks"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		err := ClientSession.Network.Delete(networkList, 0, c.Bool("force"))
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Show details of a network",
	ArgsUsage: "NETWORKREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <network_name>."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Inspecting networks"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		network, err := ClientSession.Network.Inspect(c.Args().First(), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of network", false).Error())))
		}

		// Convert struct to map using struct to json then json to map
		mapped := map[string]interface{}{}
		jsoned, err := json.Marshal(network)
		if err != nil {
			return err
		}
		err = json.Unmarshal(jsoned, &mapped)
		if err != nil {
			return err
		}

		if len(network.Subnets) == 1 {
			if network.Subnets[0] == network.Name {
				if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
					description := "Inspecting subnetworks"
					pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
					go func() {
						for {
							if pb.IsFinished() {
								return
							}
							err := pb.Add(1)
							if err != nil {
								return
							}
							time.Sleep(100 * time.Millisecond)
						}
					}()

					defer func() {
						_ = pb.Finish()
					}()
				}

				subnet, err := ClientSession.Subnet.Inspect(network.Id, network.Name, 0)
				if err != nil {
					err = fail.FromGRPCStatus(err)
					return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of network", false).Error())))
				}

				subnetMapped := map[string]interface{}{}
				jsoned, err := json.Marshal(subnet)
				if err != nil {
					return err
				}
				err = json.Unmarshal(jsoned, &subnetMapped)
				if err != nil {
					return err
				}

				for k, v := range subnetMapped {
					switch k {
					case "name":
						k = "subnet_name"
					case "id":
						k = "subnet_id"
					case "cidr":
						k = "subnet_cidr"
					case "state":
						k = "subnet_state"
					}
					mapped[k] = v
				}

				staltnum, ok := mapped["subnet_state"].(float64)
				if ok {
					mapped["subnet_state_label"] = subnetstate.Enum(int32(staltnum)).String()
				}

				if err = queryGatewaysInformation(ClientSession, subnet, mapped, false); err != nil {
					return err
				}

				delete(mapped, "subnets")
			}
		}

		return clitools.SuccessResponse(mapped)
	},
}

// Get gateway(s) information
func queryGatewaysInformation(session *client.Session, subnet *protocol.Subnet, mapped map[string]interface{}, subnetContext bool) (err error) {
	var pgw, sgw *protocol.Host
	gwIDs := subnet.GetGatewayIds()

	var gateways = make(map[string]string, len(gwIDs))
	if len(gwIDs) > 0 {
		pgw, err = session.Host.Inspect(gwIDs[0], 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			var what string
			if len(gwIDs) > 1 {
				what = "primary "
			}
			xerr := fail.Wrap(err, fmt.Sprintf("failed to inspect network: cannot inspect %sgateway", what))
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(xerr.Error())))
		}
		gateways[pgw.Name] = pgw.Id
	}
	if len(gwIDs) > 1 {
		sgw, err = session.Host.Inspect(gwIDs[1], 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			xerr := fail.Wrap(err, "failed to inspect network: cannot inspect secondary gateway")
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(xerr.Error())))
		}
		gateways[sgw.Name] = sgw.Id
	}
	if len(gateways) > 0 {
		switch subnetContext {
		case true:
			mapped["gateways"] = gateways
		case false:
			mapped["subnet_gateways"] = gateways
		}
	}
	delete(mapped, "gateway_ids")

	// Remove entry 'virtual_ip' if empty
	if _, ok := mapped["virtual_ip"]; ok && len(mapped["virtual_ip"].(map[string]interface{})) == 0 {
		delete(mapped, "virtual_ip")
	}

	return nil
}

var networkCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a network",
	ArgsUsage: "NETWORKREF",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cidr, N",
			Value: "",
			Usage: "CIDR of the Network (default: 192.168.0.0/23)",
		},
		cli.BoolFlag{
			Name:  "empty, no-default-subnet",
			Usage: "Do not create a default Subnet with the same name than the Network",
		},
		cli.BoolFlag{
			Name:  "keep-on-failure, k",
			Usage: "If used, the resource(s) is(are) not deleted on failure (default: not set)",
		},
		cli.StringFlag{
			Name:  "os",
			Usage: `Image name for the gateway`,
		},
		cli.StringFlag{
			Name:  "gwname",
			Value: "",
			Usage: "Name for the gateway. Default to 'gw-<network_name>'",
		},
		cli.IntFlag{
			Name:  "gwport, default-ssh-port",
			Value: 22,
			Usage: `Define the port to use for SSH (default: 22) in default subnet;
			Meaningful only if --empty is not used`,
		},
		cli.BoolFlag{
			Name: "failover",
			Usage: `creates 2 gateways for the network with a VIP used as internal default route;
			Meaningful only if --empty is not used`,
		},
		cli.StringFlag{
			Name: "sizing, S",
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
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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

		gatewaySSHPort := uint32(c.Int("gwport"))

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Creating network"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		network, err := ClientSession.Network.Create(
			c.Args().Get(0), c.String("cidr"), c.Bool("empty"),
			c.String("gwname"), gatewaySSHPort, c.String("os"), sizing,
			c.Bool("keep-on-failure"),
			0,
		)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of network", true).Error())))
		}
		return clitools.SuccessResponse(network)
	},
}

// networkSecurityGroupCommand command
var networkSecurityCommands = cli.Command{
	Name:  securityCmdLabel,
	Usage: "manages security of networks",
	Subcommands: cli.Commands{
		networkSecurityGroupCommands,
	},
}

// networkSecurityGroupCommand command
var networkSecurityGroupCommands = cli.Command{
	Name:    groupCmdLabel,
	Aliases: []string{"sg"},
	Usage:   groupCmdLabel + " COMMAND",
	Subcommands: cli.Commands{
		networkSecurityGroupList,
		networkSecurityGroupCreate,
		networkSecurityGroupDelete,
		networkSecurityGroupInspect,
		networkSecurityGroupClear,
		networkSecurityGroupBonds,
		networkSecurityGroupRuleCommand,
	},
}

var networkSecurityGroupList = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "List available Security Groups (created by SafeScale)",
	ArgsUsage: "[NETWORKREF]",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "List all Security Groups on tenant (not only those created by SafeScale)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel,
			c.Command.Name, c.Args(),
		)

		// networkRef := c.Args().First()

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Listing security groups"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		list, err := ClientSession.SecurityGroup.List(c.Bool("all"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of Security Groups", false).Error())))
		}
		if len(list.SecurityGroups) > 0 {
			var resp []interface{}
			for _, v := range list.SecurityGroups {
				item, xerr := reformatSecurityGroup(v, false)
				if xerr != nil {
					return clitools.FailureResponse(
						clitools.ExitOnErrorWithMessage(
							exitcode.Run, strprocess.Capitalize(xerr.Error()),
						),
					)
				}
				resp = append(resp, item)
			}
			return clitools.SuccessResponse(resp)
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkSecurityGroupInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Shows details of Security Group",
	ArgsUsage: "NETWORKREF GROUPREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel,
			c.Command.Name, c.Args(),
		)

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Inspecting security groups"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		resp, err := ClientSession.SecurityGroup.Inspect(c.Args().Get(1), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		formatted, err := reformatSecurityGroup(resp, true)
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
				item, ok := v.(map[string]interface{})
				if !ok {
					return nil, fail.NewError("rules MUST be map[string]interface{}")
				}
				direction, ok := item["direction"].(float64)
				if !ok {
					return nil, fail.NewError("direction MUST be float64")
				}
				etherType, ok := item["ether_type"].(float64)
				if !ok {
					return nil, fail.NewError("etherType MUST be float64")
				}
				item["direction_label"] = strings.ToLower(securitygroupruledirection.Enum(direction).String())
				item["ether_type_label"] = strings.ToLower(ipversion.Enum(etherType).String())
			}
		} else {
			out["rules"] = struct{}{}
		}
	}

	return out, nil
}

var networkSecurityGroupCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a new Security Group",
	ArgsUsage: "NETWORKREF GROUPREF",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "description, comment, d",
			Usage: "Describe the Security Group",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel,
			c.Command.Name, c.Args(),
		)

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		req := abstract.SecurityGroup{
			Name:        c.Args().Get(1),
			Description: c.String("description"),
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Creating security groups"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		resp, err := ClientSession.SecurityGroup.Create(c.Args().First(), req, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of security-group", true).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

// networkSecurityGroupClear ...
var networkSecurityGroupClear = cli.Command{
	Name:      "clear",
	Aliases:   []string{"reset"},
	Usage:     "deletes all rules of a Security Group",
	ArgsUsage: "NETWORKREF GROUPREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel,
			c.Command.Name, c.Args(),
		)

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Clearing security groups"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		err := ClientSession.SecurityGroup.Clear(c.Args().Get(1), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "reset of a security-group", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkSecurityGroupDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Remove Security Group",
	ArgsUsage: "NETWORKREF GROUPREF [GROUPREF ...]",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "force",
			Usage: "Force deletion, removing from hosts and networks if needed",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%v'", networkCmdLabel, securityCmdLabel, groupCmdLabel,
			c.Command.Name, c.Args(),
		)

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Deleting security groups"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		err := ClientSession.SecurityGroup.Delete(c.Args().Tail(), c.Bool("force"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of security-group", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var networkSecurityGroupBonds = cli.Command{
	Name:      "bonds",
	Aliases:   []string{"links", "attachments"},
	Usage:     "List resources Security Group is bound to",
	ArgsUsage: "NETWORKREF GROUPREF",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "kind",
			Value: "all",
			Usage: "Narrow to the kind of resource specified; can be 'hosts', 'subnets' or 'all' (default: 'all')",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel,
			c.Command.Name, c.Args(),
		)

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
		}

		kind := strings.ToLower(c.String("kind"))

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Binding security groups"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		list, err := ClientSession.SecurityGroup.Bonds(c.Args().Get(1), kind, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bonds of Security Groups", false).Error())))
		}
		result := map[string]interface{}{}
		if len(list.Hosts) > 0 {
			hosts := make([]map[string]interface{}, len(list.Hosts))
			jsoned, err := json.Marshal(list.Hosts)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "bonds of security-groups", false).Error())))
			}

			err = json.Unmarshal(jsoned, &hosts)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "bonds of security-groups", false).Error())))
			}
			result["hosts"] = hosts
		}
		if len(list.Subnets) > 0 {
			subnets := make([]map[string]interface{}, len(list.Subnets))
			jsoned, err := json.Marshal(list.Subnets)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "bonds of security-groups", false).Error())))
			}

			err = json.Unmarshal(jsoned, &subnets)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "list of security-groups", false).Error())))
			}
			result["subnets"] = subnets
		}
		if len(result) > 0 {
			return clitools.SuccessResponse(result)
		}
		return clitools.SuccessResponse(nil)
	},
}

const ruleCmdLabel = "rule"

// networkSecurityGroupRuleCommand command
var networkSecurityGroupRuleCommand = cli.Command{
	Name:      ruleCmdLabel,
	Usage:     "manages rules in Security Groups of Networks",
	ArgsUsage: "NETWORKREF|- GROUPREF",
	Subcommands: cli.Commands{
		networkSecurityGroupRuleAdd,
		networkSecurityGroupRuleDelete,
	},
}

// networkSecurityGroupRuleAdd ...
// NETWORKREF is not really used (Security Group Name are unique across the tenant by design), but kept for command consistency
var networkSecurityGroupRuleAdd = cli.Command{
	Name:      "add",
	Aliases:   []string{"new"},
	Usage:     "add a new rule to a Security Group",
	ArgsUsage: "NETWORKREF|- GROUPREF",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "description",
			Value: "",
		},
		cli.StringFlag{
			Name:  "direction, D",
			Value: "",
			Usage: "ingress or egress",
		},
		cli.StringFlag{
			Name:  "protocol, P",
			Value: "tcp",
			Usage: "Protocol",
		},
		cli.StringFlag{
			Name:  "type, T",
			Value: "ipv4",
			Usage: "ipv4 or ipv6",
		},
		cli.IntFlag{
			Name:  "port-from",
			Value: 0,
			Usage: "first port of the rule",
		},
		cli.IntFlag{
			Name:  "port-to",
			Value: 0,
			Usage: "last port of the rule",
		},
		cli.StringSliceFlag{
			Name:  "cidr, N",
			Usage: "source/target of the rule; may be used multiple times",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel,
			c.Command.Name, c.Args(),
		)

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

		rule := abstract.NewSecurityGroupRule()
		rule.Description = c.String("description")
		rule.EtherType = etherType
		rule.Direction = direction
		rule.Protocol = c.String("protocol")
		rule.PortFrom = int32(c.Int("port-from"))
		rule.PortTo = int32(c.Int("port-to"))
		rule.Targets = c.StringSlice("cidr")

		switch rule.Direction {
		case securitygroupruledirection.Ingress:
			rule.Sources = c.StringSlice("cidr")
		case securitygroupruledirection.Egress:
			rule.Targets = c.StringSlice("cidr")
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Adding rules to security groups"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		if err := ClientSession.SecurityGroup.AddRule(c.Args().Get(0), c.Args().Get(1), rule, 0); err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "addition of a rule to a security-group", true).Error())))
		}

		return clitools.SuccessResponse(nil)
	},
}

// networkSecurityGroupRuleDelete ...
// NETWORKREF is not really used (Security Group Name are unique across the tenant by design), but kept for command consistency
var networkSecurityGroupRuleDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove", "destroy"},
	Usage:     "delete a rule from a Security Group",
	ArgsUsage: "NETWORKREF|- GROUPREF",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "direction, D",
			Value: "",
			Usage: "ingress or egress",
		},
		cli.StringFlag{
			Name:  "protocol, P",
			Value: "tcp",
			Usage: "Protocol",
		},
		cli.StringFlag{
			Name:  "type, T",
			Value: "ipv4",
			Usage: "ipv4 or ipv6",
		},
		cli.IntFlag{
			Name:  "port-from",
			Value: 0,
			Usage: "first port of the rule",
		},
		cli.IntFlag{
			Name:  "port-to",
			Value: 0,
			Usage: "last port of the rule",
		},
		cli.StringSliceFlag{
			Name:  "cidr, N",
			Usage: "source/target of the rule",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, securityCmdLabel, groupCmdLabel,
			c.Command.Name, c.Args(),
		)

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

		rule := abstract.NewSecurityGroupRule()
		rule.EtherType = etherType
		rule.Direction = direction
		rule.Protocol = c.String("protocol")
		rule.PortFrom = int32(c.Int("port-from"))
		rule.PortTo = int32(c.Int("port-to"))

		switch rule.Direction {
		case securitygroupruledirection.Ingress:
			rule.Sources = c.StringSlice("cidr")
		case securitygroupruledirection.Egress:
			rule.Targets = c.StringSlice("cidr")
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Deleting rule from security group"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		err := ClientSession.SecurityGroup.DeleteRule(c.Args().Get(1), rule, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of a rule from a security-group", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

const subnetCmdLabel = "subnet"

// SubnetCommands command
var subnetCommands = cli.Command{
	Name:  subnetCmdLabel,
	Usage: "manages Subnets of Networks",
	Subcommands: cli.Commands{
		subnetCreate,
		subnetDelete,
		subnetInspect,
		subnetList,
		subnetVIPCommands,
		subnetSecurityCommands,
	},
}

var subnetList = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "List existing Subnets (created by SafeScale)",
	ArgsUsage: "NETWORKREF",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "List all Subnets on tenant (not only those created by SafeScale)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s with args %q", networkCmdLabel, subnetCmdLabel, c.Command.Name, c.Args(),
		)

		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
		}
		networkRef := c.Args().First()
		if networkRef == "-" {
			networkRef = ""
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Listing subnets"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		resp, err := ClientSession.Subnet.List(networkRef, c.Bool("all"), 0)
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
			if err := json.Unmarshal(jsoned, &result); err != nil {
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

var subnetDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "delete SUBNETREF",
	ArgsUsage: "NETWORKREF SUBNETREF [SUBNETREF ...]",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "network, net",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "If set, force node deletion no matter what (ie. metadata inconsistency)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, c.Command.Name, c.Args(),
		)

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

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Deleting subnets"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		err := ClientSession.Subnet.Delete(networkRef, list, 0, c.Bool("force"))
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of subnet", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var subnetInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Show details of a subnet",
	ArgsUsage: "NETWORKREF SUBNETREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, c.Command.Name, c.Args(),
		)

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

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Inspecting subnet"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		subnet, err := ClientSession.Subnet.Inspect(networkRef, c.Args().Get(1), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of subnet", false).Error())))
		}

		// Convert struct to map using struct to json then json to map
		mapped := map[string]interface{}{}
		jsoned, err := json.Marshal(subnet)
		if err != nil {
			return err
		}
		err = json.Unmarshal(jsoned, &mapped)
		if err != nil {
			return err
		}

		if err = queryGatewaysInformation(ClientSession, subnet, mapped, true); err != nil {
			return err
		}

		if _, ok := mapped["state"]; ok {
			mapped["state_label"] = subnetstate.Enum(mapped["state"].(float64)).String()
		}
		mapped["gateway-failover"] = false
		if gws, ok := mapped["gateways"]; ok {
			if ok {
				if gws != nil {
					mapped["gateway-failover"] = len(mapped["gateways"].(map[string]string)) > 1
				}
			}
		}
		return clitools.SuccessResponse(mapped)
	},
}

var subnetCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a subnet",
	ArgsUsage: "NETWORKREF SUBNETREF",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cidr, N",
			Value: "",
			Usage: "cidr of the network",
		},
		cli.StringFlag{
			Name:  "os",
			Value: "",
			Usage: `Image name for the gateway`,
		},
		cli.StringFlag{
			Name:  "gwname",
			Value: "",
			Usage: "Name for the gateway. Default to 'gw-<network_name>'",
		},
		cli.IntFlag{
			Name:  "gwport",
			Value: 22,
			Usage: "port to use for SSH on the gateway",
		},
		cli.BoolFlag{
			Name:  "failover",
			Usage: "creates 2 gateways for the network with a VIP used as internal default route",
		},
		cli.BoolFlag{
			Name:  "keep-on-failure, k",
			Usage: "If used, the resource(s) is(are) not deleted on failure (default: not set)",
		},
		cli.StringFlag{
			Name: "sizing, S",
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
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Creating subnet"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		network, err := ClientSession.Subnet.Create(
			networkRef, c.Args().Get(1), c.String("cidr"), c.Bool("failover"),
			c.String("gwname"), uint32(c.Int("gwport")), c.String("os"), sizing,
			c.Bool("keep-on-failure"),
			0,
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
var subnetVIPCommands = cli.Command{
	Name:      vipCmdLabel,
	Aliases:   []string{"virtualip"},
	Usage:     "manage subnet virtual IP",
	ArgsUsage: "COMMAND",

	Subcommands: cli.Commands{
		subnetVIPCreateCommand,
		subnetVIPInspectCommand,
		subnetVIPDeleteCommand,
		subnetVIPBindCommand,
		subnetVIPUnbindCommand,
	},
}

var subnetVIPCreateCommand = cli.Command{
	Name:    "create",
	Aliases: []string{"new"},
	Usage: `creates a VIP in a Subnet of a Network.
		If NETWORKREF == -, SUBNETREF must be a Subnet ID`,
	ArgsUsage: "NETWORKREF|- SUBNETREF VIPNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel,
			c.Command.Name, c.Args(),
		)

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

var subnetVIPInspectCommand = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Show details of a VIP of a Subnet in a Network",
	ArgsUsage: "NETWORKREF|- SUBNETREF VIPNAME",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "network, net",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel,
			c.Command.Name, c.Args(),
		)

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

var subnetVIPDeleteCommand = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "destroy"},
	Usage:     "Deletes a VIP from a Subnet in a Network",
	ArgsUsage: "NETWORKREF|- SUBNETREF VIPNAME",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "network, net",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel,
			c.Command.Name, c.Args(),
		)

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

var subnetVIPBindCommand = cli.Command{
	Name:      "bind",
	Aliases:   []string{"attach"},
	Usage:     "Attach a VIP to a host",
	ArgsUsage: "NETWORKREF SUBNETREF VIPNAME HOSTNAME",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "network, net",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef(
			"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel,
			c.Command.Name, c.Args(),
		)

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

var subnetVIPUnbindCommand = cli.Command{
	Name:      "unbind",
	Aliases:   []string{"detach"},
	Usage:     "unbind NETWORKREF SUBNETREF VIPNAME HOSTNAME",
	ArgsUsage: "NETWORKREF SUBNETREF VIPNAME HOSTNAME",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "network, net",
			Value: "",
			Usage: "defines the network where to search for the subnet, when a same subnet name is used in several networks",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel,
			c.Command.Name, c.Args())

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
var subnetSecurityCommands = cli.Command{
	Name:      securityCmdLabel,
	Usage:     "manages security of subnets",
	ArgsUsage: "NETWORKREF|- SUBNETREF GROUPREF",
	Subcommands: cli.Commands{
		subnetSecurityGroupCommands,
	},
}

const groupCmdLabel = "group"

// subnetSecurityGroupCommand command
var subnetSecurityGroupCommands = cli.Command{
	Name:  groupCmdLabel,
	Usage: "manages security group of subnets",
	Subcommands: cli.Commands{
		subnetSecurityGroupAddCommand,
		subnetSecurityGroupRemoveCommand,
		subnetSecurityGroupListCommand,
	},
}

var subnetSecurityGroupAddCommand = cli.Command{
	Name:      "add",
	Aliases:   []string{"attach", "bind"},
	Usage:     "Add a security group to a subnet",
	ArgsUsage: "NETWORKREF|- SUBNETREF GROUPREF",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "disabled",
			Usage: "adds the security group to the network without applying its rules",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Binding security group to subnet"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		err := ClientSession.Subnet.BindSecurityGroup(networkRef, c.Args().Get(1), c.Args().Get(2), !c.Bool("disabled"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "adding security group to network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var subnetSecurityGroupRemoveCommand = cli.Command{
	Name:      "remove",
	Aliases:   []string{"rm", "detach", "unbind"},
	Usage:     "removes a security group from a subnet",
	ArgsUsage: "NETWORKREF SUBNETREF GROUPREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Unbinding security group"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		err := ClientSession.Subnet.UnbindSecurityGroup(networkRef, c.Args().Get(1), c.Args().Get(2), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "removing security group from network", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var subnetSecurityGroupListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"show", "ls"},
	Usage:     "lists security groups bound to subnet",
	ArgsUsage: "NETWORKREF SUBNETREF",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "List all security groups no matter what is the status (enabled or disabled)",
		},
		cli.StringFlag{
			Name:  "state",
			Value: "all",
			Usage: "Narrows to the security groups in defined state; can be 'enabled', 'disabled' or 'all' (default: 'all')",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
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

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Listing security group of subnet"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		list, err := ClientSession.Subnet.ListSecurityGroups(networkRef, c.Args().Get(1), state, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "listing bound security groups of subnet", false).Error())))
		}
		return clitools.SuccessResponse(list.Subnets)
	},
}
