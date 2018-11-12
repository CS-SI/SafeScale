/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/client"
	"github.com/urfave/cli"
)

// HostCmd command
var HostCmd = cli.Command{
	Name:  "host",
	Usage: "host COMMAND",
	Subcommands: []cli.Command{
		hostList,
		hostCreate,
		hostDelete,
		hostInspect,
		hostStatus,
		hostSsh,
		hostReboot,
		hostStart,
		hostStop,
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
			return fmt.Errorf("host name or ID required")
		}
		resp, err := client.New(c.GlobalInt("port")).Host.Start(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon : %v", client.DecorateError(err, "inspection of host", false))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

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
			return fmt.Errorf("host name or ID required")
		}
		resp, err := client.New(c.GlobalInt("port")).Host.Stop(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon : %v", client.DecorateError(err, "inspection of host", false))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

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
			return fmt.Errorf("host name or ID required")
		}
		resp, err := client.New(c.GlobalInt("port")).Host.Reboot(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon : %v", client.DecorateError(err, "inspection of host", false))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var hostList = cli.Command{
	Name:  "list",
	Usage: "List available hosts (created by SafeScale)",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "List all hosts on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		hosts, err := client.New(c.GlobalInt("port")).Host.List(c.Bool("all"), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon : %v", client.DecorateError(err, "list of hosts", false))
		}
		out, _ := json.Marshal(hosts.GetHosts())
		fmt.Println(string(out))

		return nil
	},
}

var hostInspect = cli.Command{
	Name:      "inspect",
	Usage:     "inspect Host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("host name or ID required")
		}
		resp, err := client.New(c.GlobalInt("port")).Host.Inspect(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon : %v", client.DecorateError(err, "inspection of host", false))
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
			return fmt.Errorf("host name or ID required")
		}
		resp, err := client.New(c.GlobalInt("port")).Host.Status(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon : %v", client.DecorateError(err, "inspection of host", false))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var hostCreate = cli.Command{
	Name:      "create",
	Usage:     "create a new host",
	ArgsUsage: "<Host_name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "net",
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
			Value: 100,
			Usage: "Disk space for the host (MB)",
		},
		cli.StringFlag{
			Name:  "os",
			Value: "Ubuntu 16.04",
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
			Name:  "cpu-freq",
			Value: 0,
			Usage: "Minimum cpu frequency required for the host",
		},
		cli.BoolFlag{
			Name:  "force",
			Usage: "Force creation even if the host doesn't meet the GPU and CPU freq requirements",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("host and network name are required")
		}
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
			Force:    c.Bool("force"),
		}
		resp, err := client.New(c.GlobalInt("port")).Host.Create(def, client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon: %v", client.DecorateError(err, "creation of host", true))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var hostDelete = cli.Command{
	Name:      "delete",
	Usage:     "Delete host",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() < 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("host name or ID required")
		}

		var hostList []string
		hostList = append(hostList, c.Args().First())
		hostList = append(hostList, c.Args().Tail()...)

		_  = client.New(c.GlobalInt("port")).Host.Delete(hostList, client.DefaultExecutionTimeout)

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
			return fmt.Errorf("host name or ID required")
		}
		resp, err := client.New(c.GlobalInt("port")).Host.SSHConfig(c.Args().First())
		if err != nil {
			return fmt.Errorf("Error response from daemon : %v", client.DecorateError(err, "ssh config of host", false))
		}
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}
