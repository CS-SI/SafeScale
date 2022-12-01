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
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

const networkCmdLabel = "network"

// NetworkCommands command
func NetworkCommands() *cobra.Command {
	out := &cobra.Command{
		Use:           "network",
		Aliases:       []string{"net"},
		Short:         "network COMMAND",
		SilenceErrors: true,
	}
	out.AddCommand(
		networkCreateCommand(),
		networkDeleteCommand(),
		networkInspectCommand(),
		networkListCommand(),
		networkSecurityCommands(),
		subnetCommands(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

func networkListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:           "list",
		Aliases:       []string{"ls"},
		Short:         "List existing Networks (created by SafeScale)",
		SilenceErrors: true,
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Name(), strings.Join(args, ", "))

			all, err := c.Flags().GetBool("all")
			if err != nil {
				return cli.FailureResponse(err)
			}

			networks, err := ClientSession.Network.List(all, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of networks", false).Error())))
			}

			return cli.SuccessResponse(networks.GetNetworks())
		},
	}

	flags := out.Flags()
	flags.Bool("provider", false, "Lists all Networks available on tenant (not only those created by SafeScale)")
	flags.BoolP("all", "a", false, "Lists all Networks available on tenant (not only those created by SafeScale)")

	return out
}

func networkDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"rm", "remove"},
		Short:   "delete NETWORKREF",
		// ArgsUsage: "NETWORKREF [NETWORKREF ...]",
		SilenceErrors: true,
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			default:
			}

			force, err := c.Flags().GetBool("force")
			if err != nil {
				return cli.FailureResponse(err)
			}

			err = ClientSession.Network.Delete(args, temporal.ExecutionTimeout(), force)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of network", false).Error())))
			}

			return cli.SuccessResponse(nil)
		},
	}

	out.Flags().BoolP("force", "f", false, "If set, force node deletion no matter what (ie. metadata inconsistency)")

	return out
}

func networkInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Show details of a network",
		// ArgsUsage: "NETWORKREF",
		SilenceErrors: true,
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <network_name>."))
			}

			network, err := ClientSession.Network.Inspect(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "inspection of network", false).Error())))
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
					subnet, err := ClientSession.Subnet.Inspect(network.Id, network.Name, 0)
					if err != nil {
						err = fail.FromGRPCStatus(err)
						return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "inspection of network", false).Error())))
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

					// Deprecated
					// stnum, ok := mapped["state"].(float64)
					// if ok {
					// 	mapped["state_label"] = protocol.NetworkState_name[int32(stnum)]
					// }

					staltnum, ok := mapped["subnet_state"].(float64)
					if ok {
						mapped["subnet_state_label"] = subnetstate.Enum(int32(staltnum)).String()
					}

					if err = queryGatewaysInformation(subnet, mapped, false); err != nil {
						return err
					}

					delete(mapped, "subnets")
				}
			}

			return cli.SuccessResponse(mapped)
		},
	}
	return out
}

// Get gateway(s) information
func queryGatewaysInformation(subnet *protocol.Subnet, mapped map[string]interface{}, subnetContext bool) (err error) {
	var pgw, sgw *protocol.Host
	gwIDs := subnet.GetGatewayIds()

	var gateways = make(map[string]string, len(gwIDs))
	if len(gwIDs) > 0 {
		pgw, err = ClientSession.Host.Inspect(gwIDs[0], 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			var what string
			if len(gwIDs) > 1 {
				what = "primary "
			}
			xerr := fail.Wrap(err, fmt.Sprintf("failed to inspect network: cannot inspect %sgateway", what))
			return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(xerr.Error())))
		}
		gateways[pgw.Name] = pgw.Id
	}
	if len(gwIDs) > 1 {
		sgw, err = ClientSession.Host.Inspect(gwIDs[1], 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			xerr := fail.Wrap(err, "failed to inspect network: cannot inspect secondary gateway")
			return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(xerr.Error())))
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

func networkCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "Create a network",
		// ArgsUsage: "NETWORKREF",
		SilenceErrors: true,
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", networkCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			default:
			}

			var (
				sizing string
				err    error
			)
			empty, err := c.Flags().GetBool("empty")
			if err != nil {
				return cli.FailureResponse(err)
			}

			if !empty {
				sizing, err = constructHostDefinitionStringFromCLI(c, "sizing")
				if err != nil {
					return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
				}
			}

			gatewaySSHPort, err := c.Flags().GetUint16("gwport")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}

			var cidr string
			ipNet, err := c.Flags().GetIPNet("cidr")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}
			cidr = ipNet.String()

			gwname, err := c.Flags().GetString("gwname")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}

			os, err := c.Flags().GetString("os")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}

			keep_on_failure, err := c.Flags().GetBool("keep-on-failure")
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}

			network, err := ClientSession.Network.Create(
				args[0], cidr, empty,
				gwname, uint32(gatewaySSHPort), os, sizing,
				keep_on_failure,
				temporal.ExecutionTimeout(),
			)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "creation of network", true).Error())))
			}

			return cli.SuccessResponse(network)
		},
	}

	flags := out.Flags()
	flags.IPNetP("cidr", "N", net.IPNet{net.IPv4(192, 168, 0, 0), net.CIDRMask(23, 32)}, "CIDR of the Network (default: 192.168.0.0/23)")
	flags.Bool("empty", false, "Do not create a default Subnet with the same name as the Network")
	flags.Bool("no-default-subnet", false, "alias of --empty")
	flags.BoolP("keep-on-failure", "k", false, "If used, the resource(s) is(are) not deleted on failure (default: not set)")
	flags.String("os", "", "Image name for the gateway")
	flags.String("gwname", "", "Name for the gateway. Default to 'gw-<network_name>'")
	flags.Uint16("gwport", 22, `Define the port to use for SSH (default: 22) in default subnet;
			Meaningful only if --empty is not used`)
	flags.Int("default-ssh-port", 22, "alias to --gwport")
	flags.Bool("failover", false, `creates 2 gateways for the network with a VIP used as internal default route;
			Meaningful only if --empty is not used`)
	flags.StringP("sizing", "S", "", `Describe sizing of network gateway in format "<component><operator><value>[,...]" where:
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
			Meaningful only if --empty is not used`)

	return out
}

// networkSecurityGroupCommand command
func networkSecurityCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   hostSecurityCmdLabel,
		Short: "manages security of networks",
	}
	out.AddCommand(
		networkSecurityGroupCommands(),
	)
	return out
}

// networkSecurityGroupCommand command
func networkSecurityGroupCommands() *cobra.Command {
	out := &cobra.Command{
		Use:     groupCmdLabel,
		Aliases: []string{"sg"},
		Short:   groupCmdLabel + " COMMAND",
	}
	out.AddCommand(
		networkSecurityGroupListCommand(),
		networkSecurityGroupCreateCommand(),
		networkSecurityGroupDeleteCommand(),
		networkSecurityGroupInspectCommand(),
		networkSecurityGroupClearCommand(),
		networkSecurityGroupBondsCommand(),
		networkSecurityGroupRuleCommands(),
	)
	return out
}

func networkSecurityGroupListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available Security Groups (created by SafeScale)",
		// ArgsUsage: "[NETWORKREF]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			all, err := c.Flags().GetBool("all")
			if err != nil {
				return cli.FailureResponse(err)
			}

			list, err := ClientSession.SecurityGroup.List(all, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of Security Groups", false).Error())))
			}

			if len(list.SecurityGroups) > 0 {
				var resp []interface{}
				for _, v := range list.SecurityGroups {
					item, xerr := reformatSecurityGroup(v, false)
					if xerr != nil {
						return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(xerr.Error())))
					}

					resp = append(resp, item)
				}
				return cli.SuccessResponse(resp)
			}
			return cli.SuccessResponse(nil)
		},
	}

	out.Flags().BoolP("all", "a", false, "List all Security Groups on tenant (not only those created by SafeScale)")

	return out
}

func networkSecurityGroupInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Shows details of Security Group",
		// ArgsUsage: "NETWORKREF GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}

			resp, err := ClientSession.SecurityGroup.Inspect(args[1], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(err.Error()))
			}
			formatted, err := reformatSecurityGroup(resp, true)
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}
			return cli.SuccessResponse(formatted)
		},
	}
	return out
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

func networkSecurityGroupCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "create a new Security Group",
		// ArgsUsage: "NETWORKREF GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}

			description, err := c.Flags().GetString("description")
			if err != nil {
				return cli.FailureResponse(err)
			}

			abstractSG, _ := abstract.NewSecurityGroup()
			abstractSG.Name = args[1]
			abstractSG.Description = description
			resp, err := ClientSession.SecurityGroup.Create(args[0], *abstractSG, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "creation of security-group", true).Error())))
			}

			return cli.SuccessResponse(resp)
		},
	}

	flags := out.Flags()
	flags.StringP("description", "d", "", "Describe the group")
	flags.String("comment", "", "alias for --description")

	return out
}

// networkSecurityGroupClear ...
func networkSecurityGroupClearCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "clear",
		Aliases: []string{"reset"},
		Short:   "deletes all rules of a Security Group",
		// ArgsUsage: "NETWORKREF GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}

			err := ClientSession.SecurityGroup.Clear(args[1], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(
					cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "reset of a security-group", true).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}

func networkSecurityGroupDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"rm", "remove"},
		Short:   "Remove Security Group",
		// ArgsUsage: "NETWORKREF GROUPREF [GROUPREF ...]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%v'", networkCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}

			force, err := c.Flags().GetBool("force")
			if err != nil {
				return cli.FailureResponse(err)
			}

			err = ClientSession.SecurityGroup.Delete(args[1:], force, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of security-group", false).Error())))
			}

			return cli.SuccessResponse(nil)
		},
	}

	out.Flags().BoolP("force", "f", false, "Force deletion, removing from hosts and networks if needed")

	return out
}

func networkSecurityGroupBondsCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "bonds",
		Aliases: []string{"links", "attachments"},
		Short:   "List resources Security Group is bound to",
		// ArgsUsage: "NETWORKREF GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef(
				"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, hostSecurityCmdLabel, groupCmdLabel,
				c.Name(), strings.Join(args, ", "),
			)

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}

			kind, err := c.Flags().GetString("kind")
			if err != nil {
				return cli.FailureResponse(err)
			}

			kind = strings.ToLower(kind)

			list, err := ClientSession.SecurityGroup.Bonds(args[1], kind, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "bonds of Security Groups", false).Error())))
			}

			result := map[string]interface{}{}
			if len(list.Hosts) > 0 {
				hosts := make([]map[string]interface{}, len(list.Hosts))
				jsoned, err := json.Marshal(list.Hosts)
				if err != nil {
					return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "bonds of security-groups", false).Error())))
				}

				err = json.Unmarshal(jsoned, &hosts)
				if err != nil {
					return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "bonds of security-groups", false).Error())))
				}

				result["hosts"] = hosts
			}
			if len(list.Subnets) > 0 {
				subnets := make([]map[string]interface{}, len(list.Subnets))
				jsoned, err := json.Marshal(list.Subnets)
				if err != nil {
					return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "bonds of security-groups", false).Error())))
				}

				err = json.Unmarshal(jsoned, &subnets)
				if err != nil {
					return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of security-groups", false).Error())))
				}

				result["subnets"] = subnets
			}
			if len(result) > 0 {
				return cli.SuccessResponse(result)
			}
			return cli.SuccessResponse(nil)
		},
	}

	out.Flags().String("kind", "all", "Narrow to the kind of resource specified; can be 'hosts', 'subnets' or 'all' (default: 'all')")

	return out
}

const ruleCmdLabel = "rule"

// networkSecurityGroupRuleCommand command
func networkSecurityGroupRuleCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   ruleCmdLabel,
		Short: "manages rules in Security Groups of Networks",
		// ArgsUsage: "NETWORKREF|- GROUPREF",
	}
	out.AddCommand(
		networkSecurityGroupRuleAddCommand(),
		networkSecurityGroupRuleDeleteCommand(),
	)
	return out
}

// networkSecurityGroupRuleAdd ...
// NETWORKREF is not really used (Security Group Name are unique across the tenant by design), but kept for command consistency
func networkSecurityGroupRuleAddCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "add",
		Aliases: []string{"new"},
		Short:   "add a new rule to a Security Group",
		// ArgsUsage: "NETWORKREF|- GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}

			typeP, err := c.Flags().GetString("type")
			if err != nil {
				return cli.FailureResponse(err)
			}

			etherType, xerr := ipversion.Parse(typeP)
			if xerr != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.InvalidOption, xerr.Error()))
			}

			directionP, err := c.Flags().GetString("direction")
			if err != nil {
				return cli.FailureResponse(err)
			}

			direction, xerr := securitygroupruledirection.Parse(directionP)
			if xerr != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.InvalidOption, xerr.Error()))
			}

			rule := abstract.NewSecurityGroupRule()
			rule.Description, err = c.Flags().GetString("description")
			if err != nil {
				return cli.FailureResponse(err)
			}

			rule.EtherType = etherType
			rule.Direction = direction
			rule.Protocol, err = c.Flags().GetString("protocol")
			if err != nil {
				return cli.FailureResponse(err)
			}

			portFromP, err := c.Flags().GetUint16("port-from")
			if err != nil {
				return cli.FailureResponse(err)
			}

			rule.PortFrom = int32(portFromP)
			portToP, err := c.Flags().GetUint16("port-to")
			if err != nil {
				return cli.FailureResponse(err)
			}

			rule.PortTo = int32(portToP)
			rule.Targets, err = c.Flags().GetStringSlice("cidr")
			if err != nil {
				return cli.FailureResponse(err)
			}

			switch rule.Direction {
			case securitygroupruledirection.Ingress:
				rule.Sources, err = c.Flags().GetStringSlice("cidr")
				if err != nil {
					return cli.FailureResponse(err)
				}
			case securitygroupruledirection.Egress:
				rule.Targets, err = c.Flags().GetStringSlice("cidr")
				if err != nil {
					return cli.FailureResponse(err)
				}
			}

			err = ClientSession.SecurityGroup.AddRule(args[1], rule, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "addition of a rule to a security-group", true).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.String("description", "", "")
	flags.StringP("direction", "D", "", "ingress or egress")
	flags.StringP("protocol", "P", "tcp", "Protocol (tcp, udp or icmp")
	flags.StringP("type", "T", "ipv4", "ipv4 or ipv6")
	flags.Uint16("port-from", 0, "first port of the rule")
	flags.Uint16("port-to", 0, "last port of the rule")
	flags.StringSliceP("cidr", "C", nil, "source/target of the rule; may be used multiple times")

	return out
}

// networkSecurityGroupRuleDelete ...
// NETWORKREF is not really used (Security Group Name are unique across the tenant by design), but kept for command consistency
func networkSecurityGroupRuleDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"rm", "remove", "destroy"},
		Short:   "delete a rule from a Security Group",
		// ArgsUsage: "NETWORKREF|- GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}

			typeP, err := c.Flags().GetString("type")
			if err != nil {
				return cli.FailureResponse(err)
			}

			etherType, xerr := ipversion.Parse(typeP)
			if xerr != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.InvalidOption, xerr.Error()))
			}

			directionP, err := c.Flags().GetString("direction")
			if err != nil {
				return cli.FailureResponse(err)
			}

			direction, xerr := securitygroupruledirection.Parse(directionP)
			if xerr != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.InvalidOption, xerr.Error()))
			}

			rule := abstract.NewSecurityGroupRule()
			rule.EtherType = etherType
			rule.Direction = direction
			rule.Protocol, err = c.Flags().GetString("protocol")
			if err != nil {
				return cli.FailureResponse(err)
			}

			portFromP, err := c.Flags().GetUint16("port-from")
			if err != nil {
				return cli.FailureResponse(err)
			}

			rule.PortFrom = int32(portFromP)
			portToP, err := c.Flags().GetInt("port-to")
			if err != nil {
				return cli.FailureResponse(err)
			}

			rule.PortTo = int32(portToP)

			switch rule.Direction {
			case securitygroupruledirection.Ingress:
				rule.Sources, err = c.Flags().GetStringSlice("cidr")
				if err != nil {
					return cli.FailureResponse(err)
				}
			case securitygroupruledirection.Egress:
				rule.Targets, err = c.Flags().GetStringSlice("cidr")
				if err != nil {
					return cli.FailureResponse(err)
				}
			}

			err = ClientSession.SecurityGroup.DeleteRule(args[1], rule, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of a rule from a security-group", true).Error())))
			}

			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.StringP("direction", "D", "", "'ingress' (incoming) or 'egress' (outgoing)")
	flags.StringP("protocol", "P", "tcp", "Protocol")
	flags.StringP("type", "T", "ipv4", "ipv4 or ipv6")
	flags.Uint16("port-from", 0, "first port of the rule")
	flags.Uint16("port-to", 0, "last port of the rule")
	flags.StringSliceP("cidr", "C", nil, "source/target of the rule")

	return out
}

const subnetCmdLabel = "subnet"

// SubnetCommands command
func subnetCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   subnetCmdLabel,
		Short: "manages Subnets of Networks",
	}
	out.AddCommand(
		subnetCreateCommand(),
		subnetDeleteCommand(),
		subnetInspectCommand(),
		subnetListCommand(),
		subnetVIPCommands(),
		subnetSecurityCommands(),
	)
	return out
}

func subnetListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List existing Subnets (created by SafeScale)",
		// ArgsUsage: "NETWORKREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args %q", networkCmdLabel, subnetCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			default:
			}
			networkRef := args[0]
			if networkRef == "-" {
				networkRef = ""
			}

			all, err := c.Flags().GetBool("all")
			if err != nil {
				return cli.FailureResponse(err)
			}

			resp, err := ClientSession.Subnet.List(networkRef, all, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of subnets", false).Error())))
			}

			var result []map[string]interface{}
			subnets := resp.GetSubnets()
			if len(subnets) > 0 {
				jsoned, err := json.Marshal(subnets)
				if err != nil {
					return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of subnets", false).Error())))
				}
				if err := json.Unmarshal(jsoned, &result); err != nil {
					return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of subnets", false).Error())))
				}
				for _, v := range result {
					delete(v, "gateway_ids")
					delete(v, "state")
				}
			}
			return cli.SuccessResponse(result)
		},
	}

	out.Flags().BoolP("all", "a", false, "List all Subnets on tenant (not only those created by SafeScale)")

	return out
}

func subnetDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"rm", "remove"},
		Short:   "delete SUBNETREF",
		// ArgsUsage: "NETWORKREF SUBNETREF [SUBNETREF ...]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			}
			networkRef := args[0]
			if networkRef == "-" {
				networkRef = ""
			}

			force, err := c.Flags().GetBool("force")
			if err != nil {
				return cli.FailureResponse(err)
			}

			err = ClientSession.Subnet.Delete(networkRef, args[1:], temporal.ExecutionTimeout(), force)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of subnet", false).Error())))
			}

			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.String("network", "", "defines the network where to search for the subnet, when a same subnet name is used in several networks")
	flags.BoolP("force", "f", false, "If set, force node deletion no matter what (ie. metadata inconsistency)")

	return out
}

func subnetInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Show details of a subnet",
		// ArgsUsage: "NETWORKREF SUBNETREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			}
			networkRef := args[0]
			if networkRef == "-" {
				networkRef = ""
			}

			subnet, err := ClientSession.Subnet.Inspect(networkRef, args[1], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "inspection of subnet", false).Error())))
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

			if err = queryGatewaysInformation(subnet, mapped, true); err != nil {
				return err
			}

			mapped["state_label"] = subnetstate.Enum(mapped["state"].(float64)).String()
			mapped["gateway-failover"] = len(mapped["gateways"].(map[string]string)) > 1
			return cli.SuccessResponse(mapped)
		},
	}
	return out
}

func subnetCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "Create a subnet",
		// ArgsUsage: "NETWORKREF SUBNETREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			}
			networkRef := args[0]
			if networkRef == "-" {
				networkRef = ""
			}

			sizing, err := constructHostDefinitionStringFromCLI(c, "sizing")
			if err != nil {
				return err
			}

			cidr, err := c.Flags().GetString("cidr")
			if err != nil {
				return cli.FailureResponse(err)
			}

			failover, err := c.Flags().GetBool("failover")
			if err != nil {
				return cli.FailureResponse(err)
			}

			gwname, err := c.Flags().GetString("gwname")
			if err != nil {
				return cli.FailureResponse(err)
			}

			gwport, err := c.Flags().GetUint16("gwport")
			if err != nil {
				return cli.FailureResponse(err)
			}

			os, err := c.Flags().GetString("os")
			if err != nil {
				return cli.FailureResponse(err)
			}

			keep_on_failure, err := c.Flags().GetBool("keep-on-failure")
			if err != nil {
				return cli.FailureResponse(err)
			}

			network, err := ClientSession.Subnet.Create(
				networkRef, args[1], cidr, failover,
				gwname, uint32(gwport), os, sizing,
				keep_on_failure,
				temporal.ExecutionTimeout(),
			)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "creation of subnet", true).Error())))
			}

			return cli.SuccessResponse(network)
		},
	}

	flags := out.Flags()
	flags.StringP("cidr", "N", "", "cidr of the network")
	flags.String("os", "", "Image name for the gateway")
	flags.String("gwname", "", "Name for the gateway. Default to 'gw-<network_name>'")
	flags.Uint16("gwport", 22, "port to use for SSH on the gateway")
	flags.Bool("failover", false, "creates 2 gateways for the network with a VIP used as internal default route")
	flags.BoolP("keep-on-failure", "k", false, "If used, the resource(s) is(are) not deleted on failure (default: not set)")
	flags.StringP("sizing", "S", "", `Describe sizing of network gateway in format "<component><operator><value>[,...]" where:
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
`)

	return out
}

const vipCmdLabel = "vip"

// subnetVIPCommands handles 'network vip' commands
func subnetVIPCommands() *cobra.Command {
	out := &cobra.Command{
		Use:     vipCmdLabel,
		Aliases: []string{"virtualip"},
		Short:   "manage subnet virtual IP",
		// ArgsUsage: "COMMAND",
	}

	out.AddCommand(
		subnetVIPCreateCommand(),
		subnetVIPInspectCommand(),
		subnetVIPDeleteCommand(),
		subnetVIPBindCommand(),
		subnetVIPUnbindCommand(),
	)
	return out
}

func subnetVIPCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short: `creates a VIP in a Subnet of a Network.
		If NETWORKREF == -, SUBNETREF must be a Subnet ID`,
		// ArgsUsage: "NETWORKREF|- SUBNETREF VIPNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			case 2:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
			}

			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.NotImplemented, "creation of subnet VIP not yet implemented"))
		},
	}
	return out
}

func subnetVIPInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Show details of a VIP of a Subnet in a Network",
		// ArgsUsage: "NETWORKREF|- SUBNETREF VIPNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			case 2:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
			}

			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.NotImplemented, "inspection of subnet VIP not yet implemented"))
		},
	}

	out.Flags().String("network", "", "defines the network where to search for the subnet, when a same subnet name is used in several networks")

	return out
}

func subnetVIPDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"rm", "destroy"},
		Short:   "Deletes a VIP from a Subnet in a Network",
		// ArgsUsage: "NETWORKREF|- SUBNETREF VIPNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef(
				"SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel,
				c.Name(), strings.Join(args, ", "),
			)

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			case 2:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
			}

			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.NotImplemented, "deletion of subnet VIP not yet implemented"))
		},
	}

	out.Flags().String("network", "", "defines the network where to search for the subnet, when a same subnet name is used in several networks")

	return out
}

func subnetVIPBindCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "bind",
		Aliases: []string{"attach"},
		Short:   "Attach a VIP to a host",
		// ArgsUsage: "NETWORKREF SUBNETREF VIPNAME HOSTNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			case 2:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
			case 3:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument HOSTNAME."))
			}

			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.NotImplemented, "bind host to subnet VIP not yet implemented"))
		},
	}

	out.Flags().String("network", "", "defines the network where to search for the subnet, when a same subnet name is used in several networks")

	return out
}

func subnetVIPUnbindCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "unbind",
		Aliases: []string{"detach"},
		Short:   "unbind NETWORKREF SUBNETREF VIPNAME HOSTNAME",
		//ArgsUsage: "NETWORKREF SUBNETREF VIPNAME HOSTNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, vipCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			case 2:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument VIPNAME."))
			case 3:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument HOSTNAME."))
			}

			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.NotImplemented, "unbind host from subnet VIP not yet implemented"))
		},
	}

	out.Flags().String("network", "", "defines the network where to search for the subnet, when a same subnet name is used in several networks")

	return out
}

const hostSecurityCmdLabel = "security"

// subnetSecurityGroupCommand command
func subnetSecurityCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   hostSecurityCmdLabel,
		Short: "manages security of subnets",
		// ArgsUsage: "NETWORKREF|- SUBNETREF GROUPREF",
	}
	out.AddCommand(
		subnetSecurityGroupCommands(),
	)
	return out
}

const groupCmdLabel = "group"

// subnetSecurityGroupCommand command
func subnetSecurityGroupCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   groupCmdLabel,
		Short: "manages security group of subnets",
	}
	out.AddCommand(
		subnetSecurityGroupAddCommand(),
		subnetSecurityGroupRemoveCommand(),
		subnetSecurityGroupEnableCommand(),
		subnetSecurityGroupListCommand(),
		subnetSecurityGroupDisableCommand(),
	)
	return out
}

func subnetSecurityGroupAddCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "add",
		Aliases: []string{"attach", "bind"},
		Short:   "Add a security group to a subnet",
		// ArgsUsage: "NETWORKREF|- SUBNETREF GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			case 2:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}

			networkRef := args[0]
			if networkRef == "-" {
				networkRef = ""
			}

			disabled, err := c.Flags().GetBool("disabled")
			if err != nil {
				return cli.FailureResponse(err)
			}

			err = ClientSession.Subnet.BindSecurityGroup(networkRef, args[1], args[2], !disabled, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "adding security group to network", false).Error())))
			}

			return cli.SuccessResponse(nil)
		},
	}

	out.Flags().Bool("disabled", false, "adds the security group to the network without applying its rules")

	return out
}

func subnetSecurityGroupRemoveCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "remove",
		Aliases: []string{"rm", "detach", "unbind"},
		Short:   "removes a security group from a subnet",
		// ArgsUsage: "NETWORKREF SUBNETREF GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			case 2:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}
			networkRef := args[0]
			if networkRef == "-" {
				networkRef = ""
			}

			err := ClientSession.Subnet.UnbindSecurityGroup(networkRef, args[1], args[2], temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "removing security group from network", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}

func subnetSecurityGroupListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"show", "ls"},
		Short:   "lists security groups bound to subnet",
		// ArgsUsage: "NETWORKREF SUBNETREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%v'", networkCmdLabel, subnetCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			}
			networkRef := args[0]
			if networkRef == "-" {
				networkRef = ""
			}

			var state string
			all, err := c.Flags().GetBool("all")
			if err != nil {
				return err
			}
			if all {
				state = "all"
			} else {
				state, err = c.Flags().GetString("state")
				if err != nil {
					return err
				}
			}

			list, err := ClientSession.Subnet.ListSecurityGroups(networkRef, args[1], state, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "listing bound security groups of subnet", false).Error())))
			}
			return cli.SuccessResponse(list.Subnets)
		},
	}

	flags := out.Flags()
	flags.BoolP("all", "a", true, "List all security groups no matter what is the status (enabled or disabled)")
	flags.String("state", "all", "Narrows to the security groups in defined state; can be 'enabled', 'disabled' or 'all' (default: 'all')")

	return out
}

func subnetSecurityGroupEnableCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "enable",
		Aliases: []string{"activate"},
		Short:   "Enables a security group on a subnet",
		// ArgsUsage: "NETWORKREF SUBNETREF GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", networkCmdLabel, subnetCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			case 2:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}
			networkRef := args[0]
			if networkRef == "-" {
				networkRef = ""
			}

			err := ClientSession.Subnet.EnableSecurityGroup(networkRef, args[1], args[2], temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "enabling security group on network", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}

func subnetSecurityGroupDisableCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "disable",
		Aliases: []string{"deactivate"},
		Short:   "disable SUBNETREF GROUPREF",
		// ArgsUsage: "NETWORKREF SUBNETREF GROUPREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s %s with args '%s'", hostCmdLabel, subnetCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))

			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument NETWORKREF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SUBNETREF."))
			case 2:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument GROUPREF."))
			}

			networkRef := args[0]
			if networkRef == "-" {
				networkRef = ""
			}

			err := ClientSession.Subnet.DisableSecurityGroup(networkRef, args[1], args[2], temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "disabling bound security group on network", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}
