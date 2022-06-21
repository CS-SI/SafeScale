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
	"os"
	"strings"
	"time"

	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/v22/lib/client"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

const hostCmdLabel = "host"

// HostCommand command
var HostCommand = cli.Command{
	Name:  hostCmdLabel,
	Usage: "host COMMAND",
	Subcommands: cli.Commands{
		hostList,
		hostCreate,
		//		hostResize,
		hostDelete,
		hostInspect,
		hostStatus,
		hostSSH,
		hostReboot,
		hostStart,
		hostStop,
		hostCheckFeatureCommand,  // Deprecated
		hostAddFeatureCommand,    // Deprecated
		hostRemoveFeatureCommand, // Deprecated
		hostListFeaturesCommand,  // Deprecated
		hostSecurityCommands,
		hostFeatureCommands,
		hostTagCommands,
		hostLabelCommands,
	},
}

var hostStart = cli.Command{
	Name:      "start",
	Usage:     "start Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		hostRef := c.Args().First()
		err := ClientSession.Host.Start(hostRef, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "start of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostStop = cli.Command{
	Name:      "stop",
	Usage:     "stop Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		hostRef := c.Args().First()
		err := ClientSession.Host.Stop(hostRef, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "stop of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostReboot = cli.Command{
	Name:      "reboot",
	Usage:     "reboot Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		hostRef := c.Args().First()
		err := ClientSession.Host.Reboot(hostRef, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "reboot of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available hosts (created by SafeScale)",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "List all hosts on tenant (not only those created by SafeScale)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())

		hosts, err := ClientSession.Host.List(c.Bool("all"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of hosts", false).Error())))
		}

		jsoned, err := json.Marshal(hosts.GetHosts())
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "list of hosts", false).Error())))
		}

		var result []map[string]interface{}
		err = json.Unmarshal(jsoned, &result)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "list of hosts", false).Error())))
		}

		for _, v := range result {
			delete(v, "private_key")
			delete(v, "state")
			delete(v, "gateway_id")
		}
		return clitools.SuccessResponse(result)
	},
}

var hostInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "inspect Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		resp, err := ClientSession.Host.Inspect(c.Args().First(), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}

		var output map[string]interface{}
		jsoned, xerr := json.Marshal(resp)
		if xerr == nil {
			xerr = json.Unmarshal(jsoned, &output)
		}
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(xerr.Error())))
		}

		tags := make([]map[string]interface{}, 0)
		labels := make([]map[string]interface{}, 0)
		if items, ok := output["labels"].([]interface{}); ok && len(items) > 0 {
			for _, v := range items {
				item := v.(map[string]interface{})
				hasDefault, ok := item["has_default"].(bool)
				delete(item, "has_default")
				if ok && hasDefault {
					labels = append(labels, item)
				} else {
					delete(item, "value")
					delete(item, "default_value")
					tags = append(tags, item)
				}
			}
		}
		output["labels"] = labels
		output["tags"] = tags
		return clitools.SuccessResponse(output)
	},
}

var hostStatus = cli.Command{
	Name:      "state",
	Aliases:   []string{"status"},
	Usage:     "status Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		resp, err := ClientSession.Host.GetStatus(c.Args().First(), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "status of host", false).Error())))
		}
		formatted := make(map[string]interface{})
		formatted["name"] = resp.Name
		converted := converters.HostStateFromProtocolToEnum(resp.Status)
		formatted["status_code"] = converted
		formatted["status_label"] = converted.String()
		return clitools.SuccessResponse(formatted)
	},
}

var hostCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a new host",
	ArgsUsage: "<Host_name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "network, net",
			Value: "",
			Usage: "network name or network id",
		},
		cli.StringSliceFlag{
			Name: "subnet",
			Usage: `subnet name or id.
If subnet id is provided, '--network' is superfluous.
May be used multiple times, the first occurrence becoming the default subnet by design`,
		},
		cli.StringFlag{
			Name:  "os",
			Usage: "Image name for the host",
		},
		cli.BoolFlag{
			Name:  "single, public",
			Usage: "Create single Host without network but with public IP",
		},
		cli.StringFlag{
			Name:  "domain",
			Value: "",
			Usage: "domain name of the host (default: empty)",
		},
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "Force creation even if the host doesn't meet the GPU and CPU freq requirements",
		},
		cli.BoolFlag{
			Name:  "keep-on-failure, k",
			Usage: "If used, the resource is not deleted on failure (default: not set)",
		},
		cli.StringFlag{
			Name: "sizing, S",
			Usage: `Describe sizing of host in format "<component><operator><value>[,...]" where:
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
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%v", hostCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		sizing, err := constructHostDefinitionStringFromCLI(c, "sizing")
		if err != nil {
			return err
		}

		req := protocol.HostDefinition{
			Name:           c.Args().First(),
			ImageId:        c.String("os"),
			Network:        c.String("network"),
			Subnets:        c.StringSlice("subnet"),
			Single:         c.Bool("single"),
			Force:          c.Bool("force"),
			SizingAsString: sizing,
			KeepOnFailure:  c.Bool("keep-on-failure"),
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Creating host"
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

		resp, err := ClientSession.Host.Create(&req, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of host", true).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var hostResize = cli.Command{ // nolint
	Name:      "resize",
	Aliases:   []string{"upgrade"},
	Usage:     "resizes a host",
	ArgsUsage: "<Host_name>",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "cpu",
			Value: 1,
			Usage: "Number of return CPU for the host",
		},
		cli.Float64Flag{
			Name:  "ram",
			Value: 1,
			Usage: "RAM for the host (GB)",
		},
		cli.IntFlag{
			Name:  "disk",
			Value: 16,
			Usage: "Disk space for the host (GB)",
		},
		cli.IntFlag{
			Name:  "gpu",
			Value: 0,
			Usage: "Number of GPU for the host",
		},
		cli.Float64Flag{
			Name:  "cpu-freq, cpufreq",
			Value: 0,
			Usage: "Minimum cpu frequency required for the host (GHz)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}
		if c.NumFlags() == 0 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing arguments, a resize command requires that at least one argument (cpu, ram, disk, gpu, freq) is specified"))
		}

		def := protocol.HostDefinition{
			Name:     c.Args().First(),
			CpuCount: int32(c.Int("cpu")),
			Disk:     int32(c.Float64("disk")),
			Ram:      float32(c.Float64("ram")),
			GpuCount: int32(c.Int("gpu")),
			CpuFreq:  float32(c.Float64("cpu-freq")),
			Force:    c.Bool("force"),
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Resizing host"
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

		resp, err := ClientSession.Host.Resize(&def, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of host", true).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var hostDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Remove host",
	ArgsUsage: "<Host_name|Host_ID> [<Host_name|Host_ID>...]",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}
		var hostList []string
		hostList = append(hostList, c.Args().First())
		hostList = append(hostList, c.Args().Tail()...)

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Deleting host"
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

		if err := ClientSession.Host.Delete(hostList, 0); err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostSSH = cli.Command{
	Name:      "ssh",
	Usage:     "Get ssh config to connect to host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Getting SSH config"
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

		resp, err := ClientSession.Host.SSHConfig(c.Args().First())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh config of host", false).Error())))
		}

		out, xerr := formatSSHConfig(resp)
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(xerr.Error())))
		}
		return clitools.SuccessResponse(out)
	},
}

func formatSSHConfig(in sshapi.Config) (map[string]interface{}, fail.Error) {
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

// hostListFeaturesCommand handles 'safescale host list-features'
var hostListFeaturesCommand = cli.Command{
	Name:      "list-features",
	Aliases:   []string{"list-available-features"},
	Usage:     "!DEPRECATED! See safescale host feature list instead!",
	ArgsUsage: "",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "Lists all features available",
		},
	},

	Action: hostFeatureListAction,
}

// hostAddFeatureCommand handles 'safescale host add-feature <host name or id> <pkgname>'
var hostAddFeatureCommand = cli.Command{
	Name:      "add-feature",
	Aliases:   []string{"install-feature"},
	Usage:     "!DEPRECATED! See safescale host feature add instead!",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow defining content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
		cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disable reverse proxy rules",
		},
	},

	Action: hostFeatureAddAction,
}

// hostCheckFeatureCommand handles 'safescale host check-feature <host name or id> <pkgname>'
var hostCheckFeatureCommand = cli.Command{
	Name:      "check-feature",
	Aliases:   []string{"verify-feature"},
	Usage:     "!DEPRECATED! See safescale host feature check instead!",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow defining content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
	},

	Action: hostFeatureCheckAction,
}

// hostRemoveFeatureCommand handles 'safescale host delete-feature <host name> <feature name>'
var hostRemoveFeatureCommand = cli.Command{
	Name:      "remove-feature",
	Aliases:   []string{"rm-feature", "delete-feature", "uninstall-feature"},
	Usage:     "!DEPRECATED! See safescale host feature delete instead!",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Define value of feature parameter (can be used multiple times) (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
	},

	Action: hostFeatureRemoveAction,
}

// hostSecurityCommands commands
var hostSecurityCommands = cli.Command{
	Name:  securityCmdLabel,
	Usage: "Manages host security",
	Subcommands: cli.Commands{
		hostSecurityGroupCommands,
	},
}

// networkSecurityGroupCommands commands
var hostSecurityGroupCommands = cli.Command{
	Name:  groupCmdLabel,
	Usage: "Manages host Security Groups",
	Subcommands: cli.Commands{
		hostSecurityGroupAddCommand,
		hostSecurityGroupRemoveCommand,
		hostSecurityGroupEnableCommand,
		hostSecurityGroupListCommand,
		hostSecurityGroupDisableCommand,
	},
}

var hostSecurityGroupAddCommand = cli.Command{
	Name:      "add",
	Aliases:   []string{"attach", "bind"},
	Usage:     "add HOSTNAME GROUPNAME",
	ArgsUsage: "HOSTNAME GROUPNAME",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "disabled",
			Usage: "adds the security group to the host but does not activate it",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Binding security group"
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

		err := ClientSession.Host.BindSecurityGroup(c.Args().First(), c.Args().Get(1), c.Bool("disabled"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh config of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostSecurityGroupRemoveCommand = cli.Command{
	Name:      "remove",
	Aliases:   []string{"rm", "detach", "unbind"},
	Usage:     "remove HOSTNAME GROUPNAME",
	ArgsUsage: "HOSTNAME GROUPNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
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

		err := ClientSession.Host.UnbindSecurityGroup(c.Args().First(), c.Args().Get(1), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh config of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostSecurityGroupListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"show", "ls"},
	Usage:     "list HOSTNAME",
	ArgsUsage: "HOSTNAME",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "List all security groups no matter what is the status (enabled or disabled)",
		},
		cli.StringFlag{
			Name:  "state",
			Value: "all",
			Usage: "Narrow to the security groups in asked status; can be 'enabled', 'disabled' or 'all' (default: 'all')",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		state := strings.ToLower(c.String("state"))
		if c.Bool("all") {
			state = "all"
		}

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

		resp, err := ClientSession.Host.ListSecurityGroups(c.Args().First(), state, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh config of host", false).Error())))
		}

		out, err := reformatHostGroups(resp.Hosts)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateTimeoutError(err, "formatting of result", false).Error())))
		}
		return clitools.SuccessResponse(out)
	},
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

var hostSecurityGroupEnableCommand = cli.Command{
	Name:      "enable",
	Aliases:   []string{"activate"},
	Usage:     "enable NETWORKNAME GROUPNAME",
	ArgsUsage: "NETWORKNAME GROUPNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Enabling security groups"
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

		err := ClientSession.Host.EnableSecurityGroup(c.Args().First(), c.Args().Get(1), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "enable security group of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostSecurityGroupDisableCommand = cli.Command{
	Name:      "disable",
	Aliases:   []string{"deactivate"},
	Usage:     "disable HOSTNAME GROUPNAME",
	ArgsUsage: "HOSTNAME GROUPNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s %s with args '%s'", hostCmdLabel, securityCmdLabel, groupCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Disabling security group"
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

		err := ClientSession.Host.DisableSecurityGroup(c.Args().First(), c.Args().Get(1), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "disable security group of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

const hostFeatureCmdLabel = "feature"

// HostFeatureCommands command
var hostFeatureCommands = cli.Command{
	Name:  hostFeatureCmdLabel,
	Usage: hostFeatureCmdLabel + " COMMAND",
	Subcommands: cli.Commands{
		hostFeatureCheckCommand,
		hostFeatureInspectCommand,
		hostFeatureExportCommand,
		hostFeatureAddCommand,
		hostFeatureRemoveCommand,
		hostFeatureListCommand,
	},
}

// hostFeatureListCommand handles 'safescale host feature list'
var hostFeatureListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "List the available features for the host",
	ArgsUsage: "HOSTNAME",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "all",
			// Value: false,
			Usage: "If used, will list all features that are eligible to be installed on the host",
		},
	},

	Action: hostFeatureListAction,
}

func hostFeatureListAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostFeatureCmdLabel, c.Command.Name, c.Args())

	hostName, _, err := extractHostArgument(c, 0, DoNotInstanciate)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		description := "Listing host features"
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

	list, err := ClientSession.Host.ListFeatures(hostName, c.Bool("all"), 0)
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
	}

	return clitools.SuccessResponse(list)
}

// hostFeatureInspectCommand handles 'safescale host feature inspect <cluster name or id> <feature name>'
// Displays information about the feature (parameters, if eligible on host, if installed, ...)
var hostFeatureInspectCommand = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Inspects the feature",
	ArgsUsage: "",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "embedded",
			Usage: "if used, tells to show details of embedded feature (if it exists)",
		},
	},

	Action: hostFeatureInspectAction,
}

func hostFeatureInspectAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())

	hostName, _, err := extractHostArgument(c, 0, DoNotInstanciate)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	featureName, err := extractFeatureArgument(c)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		description := "Inspecting host features"
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

	details, err := ClientSession.Host.InspectFeature(hostName, featureName, c.Bool("embedded"), 0) // FIXME: set timeout
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
	}

	return clitools.SuccessResponse(details)
}

// hostFeatureExportCommand handles 'safescale cluster feature export <cluster name or id> <feature name>'
var hostFeatureExportCommand = cli.Command{
	Name:      "export",
	Aliases:   []string{"dump"},
	Usage:     "Export feature file content",
	ArgsUsage: "",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "embedded",
			Usage: "if used, tells to export embedded feature (if it exists)",
		},
		cli.BoolFlag{
			Name:  "raw",
			Usage: "outputs only the feature content, without json",
		},
	},

	Action: hostFeatureExportAction,
}

func hostFeatureExportAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s with args '%s'", hostCmdLabel, c.Command.Name, c.Args())

	hostName, _, err := extractHostArgument(c, 0, DoNotInstanciate)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	featureName, err := extractFeatureArgument(c)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
		description := "Exporting host features"
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

	export, err := ClientSession.Host.ExportFeature(hostName, featureName, c.Bool("embedded"), 0) // FIXME: set timeout
	if err != nil {
		err = fail.FromGRPCStatus(err)
		return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
	}

	if c.Bool("raw") {
		return clitools.SuccessResponse(export.Export)
	}

	return clitools.SuccessResponse(export)
}

// hostAddFeatureCommand handles 'deploy host <host name or id> package <pkgname> add'
var hostFeatureAddCommand = cli.Command{
	Name:      "add",
	Aliases:   []string{"install"},
	Usage:     "Installs a feature to a host",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
		cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disable reverse proxy rules",
		},
	},

	Action: hostFeatureAddAction,
}

func hostFeatureAddAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostFeatureCmdLabel, c.Command.Name, c.Args())

	hostName, hostInstance, err := extractHostArgument(c, 0, DoInstanciate)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	featureName, err := extractFeatureArgument(c)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	values := parametersToMap(c.StringSlice("param"))
	settings := protocol.FeatureSettings{}
	settings.SkipProxy = c.Bool("skip-proxy")

	err = ClientSession.Host.AddFeature(hostInstance.Id, featureName, values, &settings, 0)
	if err != nil {
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("error adding feature '%s' on host '%s': %s", featureName, hostName, err.Error())
		return clitools.FailureResponse(clitools.ExitOnRPC(msg))
	}

	return clitools.SuccessResponse(nil)
}

// hostFeatureCheckCommand handles 'host feature check <host name or id> <pkgname>'
var hostFeatureCheckCommand = cli.Command{
	Name:      "check",
	Aliases:   []string{"verify"},
	Usage:     "checks if a feature is installed on Host",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
	},

	Action: hostFeatureCheckAction,
}

func hostFeatureCheckAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostFeatureCmdLabel, c.Command.Name, c.Args())

	_, hostInstance, err := extractHostArgument(c, 0, DoInstanciate)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	featureName, err := extractFeatureArgument(c)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	values := parametersToMap(c.StringSlice("param"))
	settings := protocol.FeatureSettings{}

	if err = ClientSession.Host.CheckFeature(hostInstance.Id, featureName, values, &settings, 0); err != nil {
		switch grpcstatus.Code(err) {
		case codes.NotFound:
			return clitools.FailureResponse(clitools.ExitOnNotFound(fail.FromGRPCStatus(err).Error()))
		default:
			return clitools.FailureResponse(clitools.ExitOnRPC(fail.FromGRPCStatus(err).Error()))
		}
	}

	return clitools.SuccessResponse(nil)
}

// hostRemoveFeatureCommand handles 'deploy host delete-feature <host name> <feature name>'
var hostFeatureRemoveCommand = cli.Command{
	Name:      "remove",
	Aliases:   []string{"rm", "delete", "uninstall", "remove"},
	Usage:     "Remove a feature from host.",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Define value of feature parameter (can be used multiple times) (format: [FEATURENAME:]PARAMNAME=PARAMVALUE)",
		},
	},

	Action: hostFeatureRemoveAction,
}

func hostFeatureRemoveAction(c *cli.Context) (ferr error) {
	defer fail.OnPanic(&ferr)
	logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostFeatureCmdLabel, c.Command.Name, c.Args())

	hostName, hostInstance, err := extractHostArgument(c, 0, DoInstanciate)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	featureName, err := extractFeatureArgument(c)
	if err != nil {
		return clitools.FailureResponse(err)
	}

	values := parametersToMap(c.StringSlice("param"))
	settings := protocol.FeatureSettings{}

	err = ClientSession.Host.RemoveFeature(hostInstance.Id, featureName, values, &settings, 0)
	if err != nil {
		err = fail.FromGRPCStatus(err)
		msg := fmt.Sprintf("failed to remove Feature '%s' on Host '%s': %s", featureName, hostName, err.Error())
		return clitools.FailureResponse(clitools.ExitOnRPC(msg))
	}

	return clitools.SuccessResponse(nil)
}

const hostTagCmdLabel = "tag"

// HostTagCommands command
var hostTagCommands = cli.Command{
	Name:  hostTagCmdLabel,
	Usage: hostTagCmdLabel + " COMMAND",
	Subcommands: cli.Commands{
		hostTagListCommand,
		hostTagBindCommand,
		hostTagUnbindCommand,
	},
}

var hostTagListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls", "show"},
	Usage:     "list Tags bound to Host",
	ArgsUsage: "HOSTNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostTagCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments HOSTNAME"))
		}

		result, err := ClientSession.Host.ListLabels(c.Args().First(), true, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "tag of host", false).Error())))
		}

		var list []map[string]interface{}
		jsoned, xerr := json.Marshal(result.Labels)
		if xerr == nil {
			xerr = json.Unmarshal(jsoned, &list)
		}
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(xerr.Error())))
		}

		var output []map[string]interface{}
		for _, v := range list {
			hasDefault, ok := v["has_default"].(bool)
			if !ok || !hasDefault {
				delete(v, "has_default")
				delete(v, "default_value")
				output = append(output, v)
			}
		}
		return clitools.SuccessResponse(output)
	},
}

var hostTagBindCommand = cli.Command{
	Name:      "bind",
	Aliases:   []string{"attach"},
	Usage:     "bind Tag to Host",
	ArgsUsage: "HOSTREF TAGREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostTagCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments HOSTREF and/or TAGREF"))
		}

		hostRef := c.Args().First()
		labelRef := c.Args().Get(1)

		// Check corresponding Label is a Tag
		label, err := ClientSession.Label.Inspect(labelRef, true, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bind Tag to Host", false).Error())))
		}

		if label.GetHasDefault() {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidArgument, fmt.Sprintf("bind Tag to Host: '%s' is a Label", c.Args().First())))
		}

		// Confirmed, can be bound
		err = ClientSession.Host.BindLabel(hostRef, labelRef, "", 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bind Tag to Host", false).Error())))
		}

		return clitools.SuccessResponse(nil)
	},
}

var hostTagUnbindCommand = cli.Command{
	Name:      "unbind",
	Aliases:   []string{"detach"},
	Usage:     "unbind Tag from Host",
	ArgsUsage: "HOSTNAME TAGNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostTagCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments <Host_name> <Tag_name>."))
		}

		hostRef := c.Args().First()
		labelRef := c.Args().Get(1)
		label, err := ClientSession.Label.Inspect(labelRef, true, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unbind Tag from Host", false).Error())))
		}

		if label.GetHasDefault() {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidArgument, fmt.Sprintf("unbind Tag from Host: '%s' is a Label", c.Args().First())))
		}

		err = ClientSession.Host.UnbindLabel(hostRef, labelRef, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unbind Tag from Host", false).Error())))
		}

		return clitools.SuccessResponse(nil)
	},
}

const hostLabelCmdLabel = "label"

// HostLabelCommands command
var hostLabelCommands = cli.Command{
	Name:  hostLabelCmdLabel,
	Usage: hostLabelCmdLabel + " COMMAND",
	Subcommands: cli.Commands{
		hostLabelListCommand,
		hostLabelInspectCommand,
		hostLabelBindCommand,
		hostLabelUnbindCommand,
		hostLabelUpdateCommand,
		hostLabelResetCommand,
	},
}

var hostLabelListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls", "show"},
	Usage:     "list Labels bound to Host",
	ArgsUsage: "HOSTNAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostLabelCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments HOSTNAME"))
		}

		result, err := ClientSession.Host.ListLabels(c.Args().First(), false, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list Labels bound to Host", false).Error())))
		}

		var output []map[string]interface{}
		jsoned, xerr := json.Marshal(result.Labels)
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

var hostLabelInspectCommand = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "insect Label bound to Host",
	ArgsUsage: "HOSTREF LABELREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostLabelCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments HOSTREF and/or LABELREF"))
		}

		hostRef := c.Args().First()
		labelRef := c.Args().Get(1)
		result, err := ClientSession.Host.InspectLabel(hostRef, labelRef, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspect Host Label", false).Error())))
		}

		if !result.GetHasDefault() {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidArgument, fmt.Sprintf("cannot inspect Host Label: '%s' is a Tag", c.Args().First())))
		}

		out := map[string]interface{}{
			"name":          result.GetName(),
			"id":            result.GetId(),
			"default_value": result.GetDefaultValue(),
			"value":         result.Value,
		}
		return clitools.SuccessResponse(out)
	},
}

var hostLabelBindCommand = cli.Command{
	Name:      "bind",
	Aliases:   []string{"attach", "add"},
	Usage:     "bind Label to Host",
	ArgsUsage: "HOSTREF LABELREF",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "value",
			Usage: "Overrides the default value of the Label for the Host",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostLabelCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments HOSTREF and/or LABELREF"))
		}

		hostRef := c.Args().First()
		labelRef := c.Args().Get(1)
		label, err := ClientSession.Label.Inspect(labelRef, false, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bind Label to Host", false).Error())))
		}

		if !label.GetHasDefault() {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidArgument, fmt.Sprintf("bind Label to Host: '%s' is a Tag", c.Args().First())))
		}

		err = ClientSession.Host.BindLabel(hostRef, labelRef, c.String("value"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bind Label to Host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostLabelUnbindCommand = cli.Command{
	Name:      "unbind",
	Aliases:   []string{"detach", "remove", "rm"},
	Usage:     "unbind Label from Host",
	ArgsUsage: "HOSTREF LABELREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostLabelCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments HOSTREF and/or LABELREF."))
		}

		hostRef := c.Args().First()
		labelRef := c.Args().Get(1)
		label, err := ClientSession.Label.Inspect(labelRef, false, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unbind Label from Host", false).Error())))
		}

		if !label.GetHasDefault() {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidArgument, fmt.Sprintf("unbind Label from Host: '%s' is a Tag", c.Args().First())))
		}

		err = ClientSession.Host.UnbindLabel(hostRef, labelRef, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unbind Label from Host", false).Error())))
		}

		return clitools.SuccessResponse(nil)
	},
}

var hostLabelUpdateCommand = cli.Command{
	Name:      "update",
	Aliases:   []string{"set", "change"},
	Usage:     "updates the value associated to the Label for the Host",
	ArgsUsage: "HOSTREF LABELREF",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "value",
			Usage: "sets the new value of the Label for the Host",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostLabelCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments HOSTREF and/or LABELREF"))
		}

		hostRef := c.Args().First()
		labelRef := c.Args().Get(1)
		label, err := ClientSession.Label.Inspect(labelRef, false, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bind Label to Host", false).Error())))
		}

		if !label.GetHasDefault() {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidArgument, fmt.Sprintf("bind Label to Host: '%s' is a Tag", c.Args().First())))
		}

		err = ClientSession.Host.UpdateLabel(hostRef, labelRef, c.String("value"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bind Label to Host", false).Error())))
		}

		return clitools.SuccessResponse(nil)
	},
}

var hostLabelResetCommand = cli.Command{
	Name:      "reset",
	Usage:     "reset the value of the Label for the Host to the default of the Label",
	ArgsUsage: "HOSTREF LABELREF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s %s with args '%s'", hostCmdLabel, hostLabelCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments HOSTREF and/or LABELREF"))
		}

		hostRef := c.Args().First()
		labelRef := c.Args().Get(1)
		label, err := ClientSession.Label.Inspect(labelRef, false, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bind Label to Host", false).Error())))
		}

		if !label.GetHasDefault() {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.InvalidArgument, fmt.Sprintf("bind Label to Host: '%s' is a Tag", c.Args().First())))
		}

		err = ClientSession.Host.ResetLabel(hostRef, labelRef, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bind Label to Host", false).Error())))
		}

		return clitools.SuccessResponse(nil)
	},
}
