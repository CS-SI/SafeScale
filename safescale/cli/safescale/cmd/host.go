/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/safescale/server/install"
	pb "github.com/CS-SI/SafeScale/safescale"
	"github.com/CS-SI/SafeScale/safescale/client"
	"github.com/CS-SI/SafeScale/utils"
	clitools "github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/enums/ExitCode"
)

// HostCmd command
var HostCmd = cli.Command{
	Name:  "host",
	Usage: "host COMMAND",
	Subcommands: []cli.Command{
		hostList,
		hostCreate,
		hostResize,
		hostDelete,
		hostInspect,
		hostStatus,
		hostSsh,
		hostReboot,
		hostStart,
		hostStop,
		hostCheckFeatureCommand,
		hostAddFeatureCommand,
		hostDeleteFeatureCommand,
		hostListFeatureCommand,
	},
}

var hostStart = cli.Command{
	Name:      "start",
	Usage:     "start Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		hostRef := c.Args().First()
		err := client.New().Host.Start(hostRef, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "start of host", false).Error()))
		}
		fmt.Printf("Host '%s' successfully started.\n", hostRef)
		return nil
	},
}

var hostStop = cli.Command{
	Name:      "stop",
	Usage:     "stop Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		hostRef := c.Args().First()
		err := client.New().Host.Stop(hostRef, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "stop of host", false).Error()))
		}

		fmt.Printf("Host '%s' successfully stopped.\n", hostRef)
		return nil
	},
}

var hostReboot = cli.Command{
	Name:      "reboot",
	Usage:     "reboot Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		hostRef := c.Args().First()
		err := client.New().Host.Reboot(hostRef, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "reboot of host", false).Error()))
		}

		fmt.Printf("Host '%s' successfully rebooted.\n", hostRef)
		return nil
	},
}

var hostList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available hosts (created by SafeScale)",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "List all hosts on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		hosts, err := client.New().Host.List(c.Bool("all"), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "list of hosts", false).Error()))
		}
		out, _ := json.Marshal(hosts.GetHosts())
		fmt.Println(string(out))

		return nil
	},
}

var hostInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "inspect Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		resp, err := client.New().Host.Inspect(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "inspection of host", false).Error()))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var hostStatus = cli.Command{
	Name:      "status",
	Usage:     "status Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		resp, err := client.New().Host.Status(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "status of host", false).Error()))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var hostCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a new host",
	ArgsUsage: "<Host_name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "net,network",
			Value: "",
			Usage: "network name or network id",
		},
		cli.IntFlag{
			Name:  "cpu",
			Value: 1,
			Usage: "Number of CPU for the host",
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
		cli.StringFlag{
			Name:  "os",
			Value: "Ubuntu 18.04",
			Usage: "Image name for the host",
		},
		cli.BoolFlag{
			Name:  "public",
			Usage: "Create with public IP",
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
		cli.BoolFlag{
			Name:  "f, force",
			Usage: "Force creation even if the host doesn't meet the GPU and CPU freq requirements",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		// hostName := c.Args().Get(1)

		def := pb.HostDefinition{
			Name:      c.Args().First(),
			CPUNumber: int32(c.Int("cpu")),
			Disk:      int32(c.Float64("disk")),
			ImageID:   c.String("os"),
			Network:   c.String("net"),
			Public:    c.Bool("public"),
			RAM:       float32(c.Float64("ram")),
			GPUNumber: int32(c.Int("gpu")),
			Freq:      float32(c.Float64("cpu-freq")),
			Force:     c.Bool("force"),
		}
		resp, err := client.New().Host.Create(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "creation of host", true).Error()))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var hostResize = cli.Command{
	Name:      "resize",
	Aliases:   []string{"upgrade"},
	Usage:     "resizes a host",
	ArgsUsage: "<Host_name>",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "cpu",
			Value: 1,
			Usage: "Number of CPU for the host",
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
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}

		if c.NumFlags() == 0 {
			fmt.Println("Missing arguments, a resize command requires that at least one argument (cpu, ram, disk, gpu, freq) is specified")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}

		def := pb.HostDefinition{
			Name:      c.Args().First(),
			CPUNumber: int32(c.Int("cpu")),
			Disk:      int32(c.Float64("disk")),
			RAM:       float32(c.Float64("ram")),
			GPUNumber: int32(c.Int("gpu")),
			Freq:      float32(c.Float64("cpu-freq")),
			Force:     c.Bool("force"),
		}
		resp, err := client.New().Host.Resize(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "creation of host", true).Error()))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var hostDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Delete host",
	ArgsUsage: "<Host_name|Host_ID> [<Host_name|Host_ID>...]",
	Action: func(c *cli.Context) error {
		if c.NArg() < 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}

		var hostList []string
		hostList = append(hostList, c.Args().First())
		hostList = append(hostList, c.Args().Tail()...)

		err := client.New().Host.Delete(hostList, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "deletion of host", false).Error()))
		}

		return nil
	},
}

var hostSsh = cli.Command{
	Name:      "ssh",
	Usage:     "Get ssh config to connect to host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		resp, err := client.New().Host.SSHConfig(c.Args().First())
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh config of host", false).Error()))
		}
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}

// hostAddFeatureCommand handles 'deploy host <host name or id> package <pkgname> add'
var hostAddFeatureCommand = cli.Command{
	Name:      "add-feature",
	Aliases:   []string{"install-feature"},
	Usage:     "add-feature HOSTNAME FEATURENAME",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
		cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disable reverse proxy rules",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractHostArgument(c, 0)
		if err != nil {
			return err
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}

		feature, err := install.NewFeature(featureName)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.", featureName)
			return clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg)
		}
		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := install.Settings{}
		settings.SkipProxy = c.Bool("skip-proxy")

		// Wait for SSH service on remote host first
		err = client.New().Ssh.WaitReady(hostInstance.ID, client.DefaultConnectionTimeout)
		if err != nil {
			msg := fmt.Sprintf("Failed to reach '%s': %s", hostName, client.DecorateError(err, "waiting ssh on host", false))
			return clitools.ExitOnRPC(msg)
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Add(target, values, settings)
		if err != nil {
			msg := fmt.Sprintf("Error adding feature '%s' on host '%s': %s", featureName, hostName, err.Error())
			return clitools.ExitOnRPC(msg)
		}
		if !results.Successful() {
			msg := fmt.Sprintf("Failed to add feature '%s' on host '%s'", featureName, hostName)
			if Debug || Verbose {
				msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
			}
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, msg)
		}

		fmt.Printf("Feature '%s' added successfully on host '%s'\n", featureName, hostName)
		return nil
	},
}

// hostCheckFeatureCommand handles 'deploy host <host name or id> package <pkgname> check'
var hostListFeatureCommand = cli.Command{
	Name:      "list-features",
	Aliases:   []string{"list-available-features"},
	Usage:     "list-features",
	ArgsUsage: "",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
	},

	Action: func(c *cli.Context) error {
		feats, err := install.ListFeatures()
		if err != nil {
			return err
		}

		for _, feat := range feats {
			view, ok := feat.(string)
			if ok {
				fmt.Println(view)
			} else {
				view = ""
			}
		}

		return nil
	},
}

// hostCheckFeatureCommand handles 'deploy host <host name or id> package <pkgname> check'
var hostCheckFeatureCommand = cli.Command{
	Name:      "check-feature",
	Aliases:   []string{"verify-feature"},
	Usage:     "check-feature HOSTNAME FEATURENAME",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractHostArgument(c, 0)
		if err != nil {
			return err
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}

		feature, err := install.NewFeature(featureName)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.", featureName)
			return clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg)
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		// Wait for SSH service on remote host first
		err = client.New().Ssh.WaitReady(hostInstance.ID, client.DefaultConnectionTimeout)
		if err != nil {
			msg := fmt.Sprintf("Failed to reach '%s': %s", hostName, client.DecorateError(err, "waiting ssh on host", false))
			return clitools.ExitOnRPC(msg)
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Check(target, values, install.Settings{})
		if err != nil {
			msg := fmt.Sprintf("Error checking if feature '%s' is installed on '%s': %s\n", featureName, hostName, err.Error())
			return clitools.ExitOnRPC(msg)
		}
		if !results.Successful() {
			msg := fmt.Sprintf("Feature '%s' not found on host '%s'", featureName, hostName)
			if Verbose || Debug {
				msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
			}
			return clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg)
		}

		fmt.Printf("Feature '%s' found on host '%s'\n", featureName, hostName)
		return nil
	},
}

// hostDeleteFeatureCommand handles 'deploy host delete-feature <host name> <feature name>'
var hostDeleteFeatureCommand = cli.Command{
	Name:      "rm-feature",
	Aliases:   []string{"remove-feature", "delete-feature", "uninstall-feature"},
	Usage:     "Remove a feature from host.",
	ArgsUsage: "HOSTNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Define value of feature parameter (can be used multiple times)",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractHostArgument(c, 0)
		if err != nil {
			return err
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}

		feature, err := install.NewFeature(featureName)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.", featureName)
			return clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg)
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		// Wait for SSH service on remote host first
		err = client.New().Ssh.WaitReady(hostInstance.ID, client.DefaultConnectionTimeout)
		if err != nil {
			msg := fmt.Sprintf("Failed to reach '%s': %s", hostName, client.DecorateError(err, "waiting ssh on host", false))
			return clitools.ExitOnRPC(msg)
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Remove(target, values, install.Settings{})
		if err != nil {
			msg := fmt.Sprintf("Error uninstalling feature '%s' on '%s': %s\n", featureName, hostName, err.Error())
			return clitools.ExitOnRPC(msg)
		}
		if !results.Successful() {
			msg := fmt.Sprintf("Failed to delete feature '%s' from host '%s'", featureName, hostName)
			if Verbose || Debug {
				msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
			}
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, msg)
		}

		fmt.Printf("Feature '%s' deleted successfully on host '%s'\n", featureName, hostName)
		return nil
	},
}
