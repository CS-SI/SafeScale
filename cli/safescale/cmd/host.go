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
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/urfave/cli"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/utils"
	clitools "github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/concurrency"
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
		hostListFeaturesCommand,
	},
}

var hostStart = cli.Command{
	Name:      "start",
	Usage:     "start Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		} else {
			hostRef := c.Args().First()
			err := client.New().Host.Start(hostRef, client.DefaultExecutionTimeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "start of host", false).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var hostStop = cli.Command{
	Name:      "stop",
	Usage:     "stop Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		} else {
			hostRef := c.Args().First()
			err := client.New().Host.Stop(hostRef, client.DefaultExecutionTimeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "stop of host", false).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var hostReboot = cli.Command{
	Name:      "reboot",
	Usage:     "reboot Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		} else {
			hostRef := c.Args().First()
			err := client.New().Host.Reboot(hostRef, client.DefaultExecutionTimeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "reboot of host", false).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
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
		response := utils.NewCliResponse()

		hosts, err := client.New().Host.List(c.Bool("all"), client.DefaultExecutionTimeout)
		if err != nil {
			response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "list of hosts", false).Error())))
		} else {
			jsoned, _ := json.Marshal(hosts.GetHosts())
			result := []map[string]interface{}{}
			err = json.Unmarshal([]byte(jsoned), &result)
			if err != nil {
				response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, utils.Capitalize(client.DecorateError(err, "list of hosts", false).Error())))
			} else {
				for _, v := range result {
					delete(v, "private_key")
					delete(v, "state")
					delete(v, "gateway_id")
				}
				response.Succeeded(result)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var hostInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "inspect Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		} else {
			resp, err := client.New().Host.Inspect(c.Args().First(), client.DefaultExecutionTimeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "inspection of host", false).Error())))
			} else {
				response.Succeeded(resp)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var hostStatus = cli.Command{
	Name:      "status",
	Usage:     "status Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		} else {
			resp, err := client.New().Host.Status(c.Args().First(), client.DefaultExecutionTimeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "status of host", false).Error())))
			} else {
				response.Succeeded(resp)
			}
		}

		return response.GetErrorWithoutMessage()
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
			Value: -1,
			Usage: "Number of GPU for the host (by default NO GPUs)",
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
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		} else {
			askedGpus := int32(c.Int("gpu"))
			if askedGpus <= -1 {
				askedGpus = -1
				logrus.Debug("No GPU parameters used")
			} else {
				if askedGpus == 0 {
					logrus.Debug("NO GPU explicitly required")
				} else {
					logrus.Debugf("GPUs required: %d", askedGpus)
				}
			}

			def := pb.HostDefinition{
				Name:     c.Args().First(),
				CpuCount: int32(c.Int("cpu")),
				Disk:     int32(c.Float64("disk")),
				ImageId:  c.String("os"),
				Network:  c.String("net"),
				Public:   c.Bool("public"),
				Ram:      float32(c.Float64("ram")),
				GpuCount: askedGpus,
				CpuFreq:  float32(c.Float64("cpu-freq")),
				Force:    c.Bool("force"),
			}
			resp, err := client.New().Host.Create(def, client.DefaultExecutionTimeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "creation of host", true).Error())))
			} else {
				response.Succeeded(resp)
			}
		}

		return response.GetErrorWithoutMessage()
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
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		} else {
			if c.NumFlags() == 0 {
				_ = cli.ShowSubcommandHelp(c)
				response.Failed(clitools.ExitOnInvalidArgument("Missing arguments, a resize command requires that at least one argument (cpu, ram, disk, gpu, freq) is specified"))
			} else {
				def := pb.HostDefinition{
					Name:     c.Args().First(),
					CpuCount: int32(c.Int("cpu")),
					Disk:     int32(c.Float64("disk")),
					Ram:      float32(c.Float64("ram")),
					GpuCount: int32(c.Int("gpu")),
					CpuFreq:  float32(c.Float64("cpu-freq")),
					Force:    c.Bool("force"),
				}
				resp, err := client.New().Host.Resize(def, client.DefaultExecutionTimeout)
				if err != nil {
					response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "creation of host", true).Error())))
				} else {
					response.Succeeded(resp)
				}
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var hostDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Delete host",
	ArgsUsage: "<Host_name|Host_ID> [<Host_name|Host_ID>...]",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		} else {
			var hostList []string
			hostList = append(hostList, c.Args().First())
			hostList = append(hostList, c.Args().Tail()...)

			err := client.New().Host.Delete(hostList, client.DefaultExecutionTimeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "deletion of host", false).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

var hostSsh = cli.Command{
	Name:      "ssh",
	Usage:     "Get ssh config to connect to host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		} else {
			resp, err := client.New().Host.SSHConfig(c.Args().First())
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh config of host", false).Error())))
			} else {
				response.Succeeded(resp)
			}
		}

		return response.GetErrorWithoutMessage()
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
		response := utils.NewCliResponse()

		err := extractHostArgument(c, 0)
		if err != nil {
			return response.Failed(err)
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return response.Failed(err)
		}

		feature, err := install.NewFeature(concurrency.RootTask(), featureName)
		if err != nil {
			//_, _ = fmt.Fprintln(os.Stderr, err.Error())
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.", featureName)
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg))
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
		err = client.New().Ssh.WaitReady(hostInstance.Id, client.DefaultConnectionTimeout)
		if err != nil {
			msg := fmt.Sprintf("Failed to reach '%s': %s", hostName, client.DecorateError(err, "waiting ssh on host", false))
			return response.Failed(clitools.ExitOnRPC(msg))
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Add(target, values, settings)
		if err != nil {
			msg := fmt.Sprintf("Error adding feature '%s' on host '%s': %s", featureName, hostName, err.Error())
			response.Failed(clitools.ExitOnRPC(msg))
		} else {
			if !results.Successful() {
				msg := fmt.Sprintf("Failed to add feature '%s' on host '%s'", featureName, hostName)
				if Debug || Verbose {
					msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
				}
				response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, msg))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}

// hostCheckFeaturesCommand handles 'safescale host <host name or id> list-features'
var hostListFeaturesCommand = cli.Command{
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
		response := utils.NewCliResponse()

		features, err := install.ListFeatures("host")
		if err != nil {
			response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
		} else {
			response.Succeeded(features)
		}

		return response.GetErrorWithoutMessage()
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
		response := utils.NewCliResponse()

		err := extractHostArgument(c, 0)
		if err != nil {
			return response.Failed(err)
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return response.Failed(err)
		}

		feature, err := install.NewFeature(concurrency.RootTask(), featureName)
		if err != nil {
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.", featureName)
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg))
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
		err = client.New().Ssh.WaitReady(hostInstance.Id, client.DefaultConnectionTimeout)
		if err != nil {
			msg := fmt.Sprintf("Failed to reach '%s': %s", hostName, client.DecorateError(err, "waiting ssh on host", false))
			return response.Failed(clitools.ExitOnRPC(msg))
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Check(target, values, install.Settings{})
		if err != nil {
			msg := fmt.Sprintf("Error checking if feature '%s' is installed on '%s': %s\n", featureName, hostName, err.Error())
			response.Failed(clitools.ExitOnRPC(msg))
		} else {
			if !results.Successful() {
				msg := fmt.Sprintf("Feature '%s' not found on host '%s'", featureName, hostName)
				if Verbose || Debug {
					msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
				}
				response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
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
		response := utils.NewCliResponse()

		err := extractHostArgument(c, 0)
		if err != nil {
			return response.Failed(err)
		}

		err = extractFeatureArgument(c)
		if err != nil {
			return response.Failed(err)
		}

		feature, err := install.NewFeature(concurrency.RootTask(), featureName)
		if err != nil {
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error()))
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.", featureName)
			return response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg))
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
		err = client.New().Ssh.WaitReady(hostInstance.Id, client.DefaultConnectionTimeout)
		if err != nil {
			msg := fmt.Sprintf("Failed to reach '%s': %s", hostName, client.DecorateError(err, "waiting ssh on host", false))
			return response.Failed(clitools.ExitOnRPC(msg))
		}

		target := install.NewHostTarget(hostInstance)
		results, err := feature.Remove(target, values, install.Settings{})
		if err != nil {
			msg := fmt.Sprintf("Error uninstalling feature '%s' on '%s': %s\n", featureName, hostName, err.Error())
			response.Failed(clitools.ExitOnRPC(msg))
		} else {
			if !results.Successful() {
				msg := fmt.Sprintf("Failed to delete feature '%s' from host '%s'", featureName, hostName)
				if Verbose || Debug {
					msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
				}
				response.Failed(clitools.ExitOnErrorWithMessage(ExitCode.Run, msg))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetErrorWithoutMessage()
	},
}
