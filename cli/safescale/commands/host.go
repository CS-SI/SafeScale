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
	cli "github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/protocol"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var hostCmdName = "host"

// HostCmd command
var HostCmd = &cli.Command{
	Name:  hostCmdName,
	Usage: "host COMMAND",
	Subcommands: []*cli.Command{
		hostList,
		hostCreate,
		hostResize,
		hostDelete,
		hostInspect,
		hostStatus,
		hostSSH,
		hostReboot,
		hostStart,
		hostStop,
		hostCheckFeatureCommand,
		hostAddFeatureCommand,
		hostRemoveFeatureCommand,
		hostListFeaturesCommand,
	},
}

var hostStart = &cli.Command{
	Name:      "start",
	Usage:     "start Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}
		hostRef := c.Args().First()
		err := client.New().Host.Start(hostRef, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "start of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostStop = &cli.Command{
	Name:      "stop",
	Usage:     "stop Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}
		hostRef := c.Args().First()
		err := client.New().Host.Stop(hostRef, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "stop of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostReboot = &cli.Command{
	Name:      "reboot",
	Usage:     "reboot Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		hostRef := c.Args().First()
		err := client.New().Host.Reboot(hostRef, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "reboot of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available hosts (created by SafeScale)",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "all",
			Usage: "List all hosts on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		hosts, err := client.New().Host.List(c.Bool("all"), temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "list of hosts", false).Error())))
		}
		jsoned, _ := json.Marshal(hosts.GetHosts())
		var result []map[string]interface{}
		err = json.Unmarshal([]byte(jsoned), &result)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(client.DecorateError(err, "list of hosts", false).Error())))
		}
		for _, v := range result {
			delete(v, "private_key")
			delete(v, "state")
			delete(v, "gateway_id")
		}
		return clitools.SuccessResponse(result)
	},
}

var hostInspect = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "inspect Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}
		resp, err := client.New().Host.Inspect(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(err.Error()))
		}
		return clitools.SuccessResponse(resp)
	},
}

var hostStatus = &cli.Command{
	Name:      "status",
	Usage:     "status Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}
		resp, err := client.New().Host.GetStatus(c.Args().First(), temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "status of host", false).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var hostCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a new host",
	ArgsUsage: "<Host_name>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "net,network",
			Value: "",
			Usage: "network name or network id",
		},
		&cli.StringFlag{
			Name:  "os",
			Value: "Ubuntu 18.04",
			Usage: "Image name for the host",
		},
		&cli.BoolFlag{
			Name:  "public",
			Usage: "Create with public IP",
		},
		&cli.BoolFlag{
			Name:  "f, force",
			Usage: "Force creation even if the host doesn't meet the GPU and CPU freq requirements",
		},
		&cli.StringFlag{
			Name: "S, sizing",
			Usage: `Describe sizing of host in format "<component><operator><value>[,...]" where:
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
		&cli.UintFlag{
			Name:  "cpu",
			Usage: "DEPRECATED! uses --sizing! Defines the number of cpu of masters and nodes in the cluster",
		},
		&cli.Float64Flag{
			Name:  "cpu-freq, cpufreq",
			Value: 0,
			Usage: "DEPRECATED! uses --sizing! Minimum cpu frequency required for the host (GHz)",
		},
		&cli.IntFlag{
			Name:  "gpu",
			Value: -1,
			Usage: "DEPRECATED! uses --sizing! Number of GPU for the host (by default NO GPUs)",
		},
		&cli.Float64Flag{
			Name:  "ram",
			Usage: "DEPRECATED! uses --sizing! Defines the size of RAM of masters and nodes in the cluster (in GB)",
		},
		&cli.UintFlag{
			Name:  "disk",
			Usage: "DEPRECATED! uses --sizing! Defines the size of system disk of masters and nodes (in GB)",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}
		askedGpus := int32(c.Int("gpu"))
		if askedGpus <= -1 {
			logrus.Debug("No GPU parameters used")
		} else {
			if askedGpus == 0 {
				logrus.Debug("NO GPU explicitly required")
			} else {
				logrus.Debugf("GPUs required: %d", askedGpus)
			}
		}

		sizing, err := constructHostDefinitionStringFromCLI(c, "sizing")
		if err != nil {
			return err
		}

		req := protocol.HostDefinition{
			Name:           c.Args().First(),
			ImageId:        c.String("os"),
			Network:        c.String("net"),
			Public:         c.Bool("public"),
			Force:          c.Bool("force"),
			SizingAsString: sizing,
		}
		resp, err := client.New().Host.Create(req, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "creation of host", true).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var hostResize = &cli.Command{
	Name:      "resize",
	Aliases:   []string{"upgrade"},
	Usage:     "resizes a host",
	ArgsUsage: "<Host_name>",
	Flags: []cli.Flag{
		&cli.IntFlag{
			Name:  "cpu",
			Value: 1,
			Usage: "Number of return CPU for the host",
		},
		&cli.Float64Flag{
			Name:  "ram",
			Value: 1,
			Usage: "RAM for the host (GB)",
		},
		&cli.IntFlag{
			Name:  "disk",
			Value: 16,
			Usage: "Disk space for the host (GB)",
		},
		&cli.IntFlag{
			Name:  "gpu",
			Value: 0,
			Usage: "Number of GPU for the host",
		},
		&cli.Float64Flag{
			Name:  "cpu-freq, cpufreq",
			Value: 0,
			Usage: "Minimum cpu frequency required for the host (GHz)",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
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
		resp, err := client.New().Host.Resize(def, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "creation of host", true).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var hostDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Delete host",
	ArgsUsage: "<Host_name|Host_ID> [<Host_name|Host_ID>...]",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}
		var hostList []string
		hostList = append(hostList, c.Args().First())
		hostList = append(hostList, c.Args().Tail()...)

		err := client.New().Host.Delete(hostList, temporal.GetExecutionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "deletion of host", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var hostSSH = &cli.Command{
	Name:      "ssh",
	Usage:     "Get ssh config to connect to host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}
		resp, err := client.New().Host.SSHConfig(c.Args().First())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateError(err, "ssh config of host", false).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

// hostListFeaturesCommand handles 'safescale host list-features'
var hostListFeaturesCommand = &cli.Command{
	Name:      "list-features",
	Aliases:   []string{"list-available-features"},
	Usage:     "list-features",
	ArgsUsage: "",

	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "all, a",
			Usage: "Lists all features available",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		features, err := client.New().Host.ListFeatures(c.Args().First(), c.Bool("all"))
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}
		return clitools.SuccessResponse(features)
	},
}

// hostAddFeatureCommand handles 'deploy host <host name or id> package <pkgname> add'
var hostAddFeatureCommand = &cli.Command{
	Name:      "add-feature",
	Aliases:   []string{"install-feature"},
	Usage:     "add-feature HOSTNAME FEATURENAME",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
		&cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disable reverse proxy rules",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		err := extractHostArgument(c, 0)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		task, err := concurrency.NewTask()
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		values := map[string]string{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := protocol.FeatureSettings{}
		settings.SkipProxy = c.Bool("skip-proxy")

		// Wait for SSH service on remote host first
		err = client.New().SSH.WaitReady(task, hostInstance.Id, temporal.GetConnectionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("failed to reach '%s': %s", hostName, client.DecorateError(err, "waiting ssh on host", false))
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		err = client.New().Host.AddFeature(hostInstance.Id, featureName, values, settings, 0)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("error adding feature '%s' on host '%s': %s", featureName, hostName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		return clitools.SuccessResponse(nil)
	},
}

// hostCheckFeatureCommand handles 'deploy host <host name or id> package <pkgname> check'
var hostCheckFeatureCommand = &cli.Command{
	Name:      "check-feature",
	Aliases:   []string{"verify-feature"},
	Usage:     "check-feature HOSTNAME FEATURENAME",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		err := extractHostArgument(c, 0)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		task, err := concurrency.NewTask()
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		values := map[string]string{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}
		settings := protocol.FeatureSettings{}

		// Wait for SSH service on remote host first
		err = client.New().SSH.WaitReady(task, hostInstance.Id, temporal.GetConnectionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("failed to reach '%s': %s", hostName, client.DecorateError(err, "waiting ssh on host", false))
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		err = client.New().Host.CheckFeature(hostInstance.Id, featureName, values, settings, 0)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("error adding feature '%s' on host '%s': %s", featureName, hostName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		return clitools.SuccessResponse(nil)
	},
}

// hostRemoveFeatureCommand handles 'deploy host delete-feature <host name> <feature name>'
var hostRemoveFeatureCommand = &cli.Command{
	Name:      "remove-feature",
	Aliases:   []string{"rm-feature", "delete-feature", "uninstall-feature"},
	Usage:     "Remove a feature from host.",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Define value of feature parameter (can be used multiple times)",
		},
	},

	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", hostCmdName, c.Command.Name, c.Args())
		err := extractHostArgument(c, 0)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return clitools.FailureResponse(err)
		}

		task, err := concurrency.NewTask()
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		values := map[string]string{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}
		settings := protocol.FeatureSettings{}

		// Wait for SSH service on remote host first
		err = client.New().SSH.WaitReady(task, hostInstance.Id, temporal.GetConnectionTimeout())
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("failed to reach '%s': %s", hostName, client.DecorateError(err, "waiting ssh on host", false))
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}

		err = client.New().Host.RemoveFeature(hostInstance.Id, featureName, values, settings, 0)
		if err != nil {
			err = scerr.FromGRPCStatus(err)
			msg := fmt.Sprintf("error removing feature '%s' on host '%s': %s", featureName, hostName, err.Error())
			return clitools.FailureResponse(clitools.ExitOnRPC(msg))
		}
		return clitools.SuccessResponse(nil)
	},
}
