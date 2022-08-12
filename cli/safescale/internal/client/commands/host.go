//go:build fixme
// +build fixme

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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/urfave/cli"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

const hostCmdLabel = "host"

// HostCommands command
func HostCommands() *cobra.Command {
	hostCommand := &cobra.Command{
		Use:   hostCmdLabel,
		Short: "host COMMAND",
	}
	hostCommand.AddCommand(
		hostListCommand(),
		hostCreateCommand(),
		//		hostResizeCommand(),
		hostDeleteCommand(),
		hostInspectCommand(),
		hostStatusCommand(),
		hostSSHCommand(),
		hostRebootCommand(),
		hostStartCommand(),
		hostStopCommand(),
		hostSecurityCommands(),
		hostFeatureCommands(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return hostCommand
}

func hostStartCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "start",
		Short: "start Host",
		// ArgsUsage: "<Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			hostRef := args[0]
			err := ClientSession.Host.Start(hostRef, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "start of host", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

func hostStopCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "stop",
		Short:     "stop Host",
		//ArgsUsage: "<Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			hostRef := args[0]
			err := ClientSession.Host.Stop(hostRef, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "stop of host", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

func hostRebootCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "reboot",
		Short: "reboot Host",
		// ArgsUsage: "<Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			hostRef := args[0]
			err := ClientSession.Host.Reboot(hostRef, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "reboot of host", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

func hostListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available hosts (created by SafeScale)",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))

			hosts, err := ClientSession.Host.List(c.Flags().GetBool("all"), 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of hosts", false).Error())))
			}

			jsoned, err := json.Marshal(hosts.GetHosts())
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of hosts", false).Error())))
			}

			var result []map[string]interface{}
			err = json.Unmarshal(jsoned, &result)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of hosts", false).Error())))
			}

			for _, v := range result {
				delete(v, "private_key")
				delete(v, "state")
				delete(v, "gateway_id")
			}
			return clitools.SuccessResponse(result)
		},
	}
	out.Flags().BoolP("all", "a", false, "List all hosts on tenant (not only those created by SafeScale)")
	return out
}

func hostInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "inspect Host",
		// ArgsUsage: "<Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			resp, err := ClientSession.Host.Inspect(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
			}

			return clitools.SuccessResponse(resp)
		},
	}
	return out
}

func hostStatusCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "state",
		Aliases:   []string{"status"},
		Short:     "status Host",
		// ArgsUsage: "<Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			resp, err := ClientSession.Host.GetStatus(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "status of host", false).Error())))
			}
			formatted := make(map[string]interface{})
			formatted["name"] = resp.Name
			converted := converters.HostStateFromProtocolToEnum(resp.Status)
			formatted["status_code"] = converted
			formatted["status_label"] = converted.String()
			return clitools.SuccessResponse(formatted)
		},
	}
	return out
}

func hostCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "create a new host",
		// ArgsUsage: "<Host_name>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%v", hostCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			sizing, err := constructHostDefinitionStringFromCLI(c, "sizing")
			if err != nil {
				return err
			}

			req := protocol.HostDefinition{
				Name:           args[0],
				ImageId:        c.Flags().GetString("os"),
				Network:        c.Flags().GetString("network"),
				Subnets:        c.Flags().GetStringSlice("subnet"),
				Single:         c.Flags().GetBool("single"),
				Force:          c.Flags().GetBool("force"),
				SizingAsString: sizing,
				KeepOnFailure:  c.Flags().GetBool("keep-on-failure"),
			}
			resp, err := ClientSession.Host.Create(&req, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "creation of host", true).Error())))
			}
			return clitools.SuccessResponse(resp)
		},
	}

	flags := out.Flags()
	flags.String("network", "", "network name or network id")
	flags.StringSlice("subnet", nil, `subnet name or id.
	If subnet id is provided, '--network' is superfluous.
	May be used multiple times, the first occurrence becoming the default subnet by design`,
	)
	flags.String("os", "", "Image name for the host")
	flags.Bool("single", false, "Create single Host without network but with public IP")
	// Aliases: []string{"public"}
	flags.String("domain", "", "domain name of the host (default: empty)")
	flags.BoolP("force", "f", false, "Force creation even if the host doesn't meet the GPU and CPU freq requirements")
	flags.BoolP("keep-on-failure", "k", false, "If used, the resource is not deleted on failure (default: not set)")
	flags.StringP("sizing", "S", "", `Describe sizing of host in format "<component><operator><value>[,...]" where:
				<component> can be cpu, cpufreq, gpu, ram, disk, template (the latter takes precedence over the formers, but corrupting the cloud-agnostic principle)
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
					--sizing "cpu <= 8, ram ~ 16"`,
	)

	return out
}

func hostResizeCommand() *cobra.Command {
	out := &cobra.Command{ // nolint
		Use:     "resize",
		Aliases: []string{"upgrade"},
		Short:   "resizes a host",
		// ArgsUsage: "<Host_name>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}
			if c.NumFlags() == 0 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing arguments, a resize command requires that at least one argument (cpu, ram, disk, gpu, freq) is specified"))
			}

			def := protocol.HostDefinition{
				Name:     args[0],
				CpuCount: int32(c.Flags().GetInt("cpu")),
				Disk:     int32(c.Float64("disk")),
				Ram:      float32(c.Float64("ram")),
				GpuCount: int32(c.Flags().GetInt("gpu")),
				CpuFreq:  float32(c.Float64("cpu-freq")),
				Force:    c.Flags().GetBool("force"),
			}
			resp, err := ClientSession.Host.Resize(&def, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "creation of host", true).Error())))
			}
			return clitools.SuccessResponse(resp)
		},
	}

	flags := out.Flags()
	flags.BoolP("force", "f", false, "Force creation even if the host doesn't meet the GPU and CPU freq requirements")
	flags.BoolP("keep-on-failure", "k", false, "If used, the resource is not deleted on failure (default: not set)")
	flags.StringP("sizing", "S", "", `Describe sizing of host in format "<component><operator><value>[,...]" where:
				<component> can be cpu, cpufreq, gpu, ram, disk, template (the latter takes precedence over the formers, but corrupting the cloud-agnostic principle)
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
					--sizing "cpu <= 8, ram ~ 16"`,
	)

	return out
}

func hostDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"rm", "remove"},
		Short:   "Remove host",
		// ArgsUsage: "<Host_name|Host_ID> [<Host_name|Host_ID>...]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) < 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			if err := ClientSession.Host.Delete(args, 0); err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of host", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

func hostSSHCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "ssh",
		Short:     "Get ssh config to connect to host",
		// ArgsUsage: "<Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) < 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			resp, err := ClientSession.Host.SSHConfig(args[0])
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "ssh config of host", false).Error())))
			}

			out, xerr := formatSSHConfig(resp)
			if xerr != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(xerr.Error())))
			}
			return clitools.SuccessResponse(out)
		},
	}
	return out
}

// hostSecurityCommands commands
func hostSecurityCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   hostSecurityCmdLabel,
		Short: "Manages host security",
	}
	out.AddCommand(
		hostSecurityGroupCommands(),
	)
	return out
}

// hostSecurityGroupCommands commands
func hostSecurityGroupCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   groupCmdLabel,
		Short: "Manages host Security Groups",
	}
	out.AddCommand(
		hostSecurityGroupAddCommand(),
		hostSecurityGroupRemoveCommand(),
		hostSecurityGroupEnableCommand(),
		hostSecurityGroupListCommand(),
		hostSecurityGroupDisableCommand(),
	)
	return out
}

func hostSecurityGroupAddCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "add",
		Aliases:   []string{"attach", "bind"},
		Short:     "add HOSTNAME GROUPNAME",
		// ArgsUsage: "HOSTNAME GROUPNAME",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "disabled",
				Value: false,
				Usage: "adds the security group to the host but does not activate it",
			},
		},
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
			}


			err := ClientSession.Host.BindSecurityGroup(args[0], c.Args().Get(1), c.Flags().GetBool("disabled"), 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "ssh config of host", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

func hostSecurityGroupRemoveCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "remove",
		Aliases:   []string{"rm", "detach", "unbind"},
		Short:     "remove HOSTNAME GROUPNAME",
		// ArgsUsage: "HOSTNAME GROUPNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
			}

			err := ClientSession.Host.UnbindSecurityGroup(args[0], c.Args().Get(1), 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "ssh config of host", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out}

func hostSecurityGroupListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "list",
		Aliases:   []string{"show", "ls"},
		Short:     "list HOSTNAME",
		// ArgsUsage: "HOSTNAME",
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
				Usage: "Narrow to the security groups in asked status; can be 'enabled', 'disabled' or 'all' (default: 'all')",
			},
		},
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
			}

			state := strings.ToLower(c.Flags().GetString("state"))
			if c.Flags().GetBool("all") {
				state = "all"
			}

			resp, err := ClientSession.Host.ListSecurityGroups(args[0], state, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "ssh config of host", false).Error())))
			}

			out, err := reformatHostGroups(resp.Hosts)
			if err != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "formatting of result", false).Error())))
			}
			return clitools.SuccessResponse(out)
		},
	}
	return out
}

func reformatHostGroups(in []*protocol.SecurityGroupBond) ([]interface{}, fail.Error) {
	out := make([]interface{}, 0, len(in))
	jsoned, err := json.Marshal(in)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	err = json.Unmarshal(jsoned, &out)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	return out, nil
}

func hostSecurityGroupEnableCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "enable",
		Aliases:   []string{"activate"},
		Short:     "enable NETWORKNAME GROUPNAME",
		// ArgsUsage: "NETWORKNAME GROUPNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
			}

			err := ClientSession.Host.EnableSecurityGroup(args[0], c.Args().Get(1), 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "enable security group of host", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

func hostSecurityGroupDisableCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "disable",
		Aliases:   []string{"deactivate"},
		Short:     "disable HOSTNAME GROUPNAME",
		// ArgsUsage: "HOSTNAME GROUPNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, hostSecurityCmdLabel, groupCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
			}

			err := ClientSession.Host.DisableSecurityGroup(args[0], c.Args().Get(1), 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "disable security group of host", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

const hostFeatureCmdLabel = "feature"

// HostFeatureCommands command
func hostFeatureCommands() *cobra.Command {
	out := &cobra.Command{
		Use:  hostFeatureCmdLabel,
		Short: hostFeatureCmdLabel + " COMMAND",
	}
	out.AddCommand(
		hostFeatureCheckCommand(),
		hostFeatureInspectCommand(),
		hostFeatureExportCommand(),
		hostFeatureAddCommand(),
		hostFeatureRemoveCommand(),
		hostFeatureListCommand(),
	)
	return out
}

// hostFeatureListCommand handles 'safescale host feature list'
func hostFeatureListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "list",
		Aliases:   []string{"ls"},
		Short:     "List the available features for the host",
		// ArgsUsage: "HOSTNAME",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostFeatureCmdLabel, c.Name(), strings.Join(args, ", "))

			hostName, _, err := extractHostArgument(c, 0, DoNotInstanciate)
			if err != nil {
				return clitools.FailureResponse(err)
			}

			list, err := ClientSession.Host.ListFeatures(hostName, c.Flags().GetBool("all"), 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
			}
			return clitools.SuccessResponse(list)
		},
	}
Flags: []cli.Flag{
	&cli.BoolFlag{
		Name:  "all",
		Value: false,
		Usage: "If used, will list all features that are eligible to be installed on the host",
	},
},
	return out
}

// hostFeatureInspectCommand handles 'safescale host feature inspect <cluster name or id> <feature name>'
// Displays information about the feature (parameters, if eligible on host, if installed, ...)
func hostFeatureInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "inspect",
		Aliases:   []string{"show"},
		Short:     "Inspects the feature",
		// ArgsUsage: "",

		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "embedded",
				Value: false,
				Usage: "if used, tells to show details of embedded feature (if it exists)",
			},
		},

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))

			hostName, _, err := extractHostArgument(c, 0, DoNotInstanciate)
			if err != nil {
				return clitools.FailureResponse(err)
			}

			featureName, err := extractFeatureArgument(c)
			if err != nil {
				return clitools.FailureResponse(err)
			}


			details, err := ClientSession.Host.InspectFeature(hostName, featureName, c.Flags().GetBool("embedded"), 0) // FIXME: set timeout
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
			}

			return clitools.SuccessResponse(details)
		},
	}
	return out
}

// hostFeatureExportCommand handles 'safescale cluster feature export <cluster name or id> <feature name>'
func hostFeatureExportCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "export",
		Aliases:   []string{"dump"},
		Short:     "Export feature file content",
		// ArgsUsage: "",

		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "embedded",
				Value: false,
				Usage: "if used, tells to export embedded feature (if it exists)",
			},
			&cli.BoolFlag{
				Name:  "raw",
				Value: false,
				Usage: "outputs only the feature content, without json",
			},
		},

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Name(), strings.Join(args, ", "))

			hostName, _, err := extractHostArgument(c, 0, DoNotInstanciate)
			if err != nil {
				return clitools.FailureResponse(err)
			}

			featureName, err := extractFeatureArgument(c)
			if err != nil {
				return clitools.FailureResponse(err)
			}


			export, err := ClientSession.Host.ExportFeature(hostName, featureName, c.Flags().GetBool("embedded"), 0) // FIXME: set timeout
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
			}

			if c.Flags().GetBool("raw") {
				return clitools.SuccessResponse(export.Export)
			}

			return clitools.SuccessResponse(export)
		},
	}
	return out
}

// hostAddFeatureCommand handles 'deploy host <host name or id> package <pkgname> add'
func hostFeatureAddCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "add",
		Aliases:   []string{"install"},
		Short:     "Installs a feature to a host",
		// ArgsUsage: "HOSTNAME FEATURENAME",

		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "param",
				Aliases: []string{"p"},
				Usage:   "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
			},
			&cli.BoolFlag{
				Name:  "skip-proxy",
				Usage: "Disable reverse proxy rules",
			},
		},

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostFeatureCmdLabel, c.Name(), strings.Join(args, ", "))

			hostName, hostInstance, err := extractHostArgument(c, 0, DoInstanciate)
			if err != nil {
				return clitools.FailureResponse(err)
			}

			featureName, err := extractFeatureArgument(c)
			if err != nil {
				return clitools.FailureResponse(err)
			}

			values := parametersToMap(c.Flags().GetStringSlice("param"))
			settings := protocol.FeatureSettings{}
			settings.SkipProxy = c.Flags().GetBool("skip-proxy")


			err = clientSession.Host.AddFeature(hostInstance.Id, featureName, values, &settings, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				msg := fmt.Sprintf("error adding feature '%s' on host '%s': %s", featureName, hostName, err.Error())
				return clitools.FailureResponse(clitools.ExitOnRPC(msg))
			}

			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

// hostFeatureCheckCommand handles 'host feature check <host name or id> <pkgname>'
func hostFeatureCheckCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "check",
		Aliases:   []string{"verify"},
		Short:     "checks if a feature is installed on Host",
		// ArgsUsage: "HOSTNAME FEATURENAME",

		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "param",
				Aliases: []string{"p"},
				Usage:   "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
			},
		},

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostFeatureCmdLabel, c.Name(), strings.Join(args, ", "))

			_, hostInstance, err := extractHostArgument(c, 0, DoInstanciate)
			if err != nil {
				return clitools.FailureResponse(err)
			}

			featureName, err := extractFeatureArgument(c)
			if err != nil {
				return clitools.FailureResponse(err)
			}

			values := parametersToMap(c.Flags().GetStringSlice("param"))
			settings := protocol.FeatureSettings{}


			if err = clientSession.Host.CheckFeature(hostInstance.Id, featureName, values, &settings, 0); err != nil {
				switch grpcstatus.Code(err) {
				case codes.NotFound:
					return clitools.FailureResponse(clitools.ExitOnNotFound(fail.FromGRPCStatus(err).Error()))
				default:
					return clitools.FailureResponse(clitools.ExitOnRPC(fail.FromGRPCStatus(err).Error()))
				}
			}

			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

// hostRemoveFeatureCommand handles 'deploy host delete-feature <host name> <feature name>'
func hostFeatureRemoveCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "remove",
		Aliases:   []string{"rm", "delete", "uninstall", "remove"},
		Short:     "Remove a feature from host.",
		// ArgsUsage: "HOSTNAME FEATURENAME",

		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "param",
				Aliases: []string{"p"},
				Usage:   "Define value of feature parameter (can be used multiple times) (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
			},
		},

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostFeatureCmdLabel, c.Name(), strings.Join(args, ", "))

			hostName, hostInstance, err := extractHostArgument(c, 0, DoInstanciate)
			if err != nil {
				return clitools.FailureResponse(err)
			}

			featureName, err := extractFeatureArgument(c)
			if err != nil {
				return clitools.FailureResponse(err)
			}

			values := parametersToMap(c.Flags().GetStringSlice("param"))
			settings := protocol.FeatureSettings{}


			err = clientSession.Host.RemoveFeature(hostInstance.Id, featureName, values, &settings, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				msg := fmt.Sprintf("failed to remove Feature '%s' on Host '%s': %s", featureName, hostName, err.Error())
				return clitools.FailureResponse(clitools.ExitOnRPC(msg))
			}

			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

func formatSSHConfig(in api.Config) (map[string]interface{}, fail.Error) {
	jsoned, err := json.Marshal(&in)
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	out := map[string]interface{}{}
	err = json.Unmarshal(jsoned, &out)
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	if anon, ok := out["primary_gateway_config"]; ok && anon == nil {
		delete(out, "primary_gateway_config")
	}
	if anon, ok := out["secondary_gateway_config"]; ok && anon == nil {
		delete(out, "secondary_gateway_config")
	}
	if anon, ok := out["port"]; ok && anon.(float64) == 0 {
		out["port"] = 22
	}
	return out, nil
}
