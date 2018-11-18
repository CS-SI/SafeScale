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

	"github.com/urfave/cli"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/client"
	clitools "github.com/CS-SI/SafeScale/utils"
)

// NetworkCmd command
var NetworkCmd = cli.Command{
	Name:  "network",
	Usage: "network COMMAND",
	Subcommands: []cli.Command{
		networkCreate,
		networkDelete,
		networkInspect,
		networkList,
	},
}

var networkList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List existing Networks (created by SafeScale)",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "List all Networks on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		networks, err := client.New().Network.List(c.Bool("all"), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "list of networks", false).Error())
		}
		out, _ := json.Marshal(networks.GetNetworks())
		fmt.Println(string(out))

		return nil
	},
}

var networkDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "delete NETWORK",
	ArgsUsage: "<network_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() < 1 {
			fmt.Println("Missing mandatory argument <network_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}

		var networkList []string
		networkList = append(networkList, c.Args().First())
		networkList = append(networkList, c.Args().Tail()...)

		err := client.New().Network.Delete(networkList, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "deletion of network", false).Error())
		}

		return nil
	},
}

var networkInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "inspect NETWORK",
	ArgsUsage: "<network_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <network_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		network, err := client.New().Network.Inspect(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "inspection of network", false).Error())
		}
		out, _ := json.Marshal(network)
		fmt.Println(string(out))

		return nil
	},
}

var networkCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a network",
	ArgsUsage: "<network_name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cidr",
			Value: "192.168.0.0/24",
			Usage: "cidr of the network",
		},
		cli.IntFlag{
			Name:  "cpu",
			Value: 1,
			Usage: "Number of CPU for the gateway",
		},
		cli.Float64Flag{
			Name:  "ram",
			Value: 1,
			Usage: "RAM for the gateway",
		},
		cli.IntFlag{
			Name:  "disk",
			Value: 16,
			Usage: "Disk space for the gateway",
		},
		cli.StringFlag{
			Name:  "os",
			Value: "Ubuntu 16.04",
			Usage: "Image name for the gateway",
		},
		cli.StringFlag{
			Name:  "gwname",
			Value: "",
			Usage: "Name for the gateway. Default to 'gw-<network_name>'",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <network_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		netdef := pb.NetworkDefinition{
			CIDR: c.String("cidr"),
			Name: c.Args().Get(0),
			Gateway: &pb.GatewayDefinition{
				CPU:  int32(c.Int("cpu")),
				Disk: int32(c.Int("disk")),
				RAM:  float32(c.Float64("ram")),
				// CPUFrequency: ??,
				ImageID: c.String("os"),
				Name:    c.String("gwname"),
			},
		}
		network, err := client.New().Network.Create(netdef, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "creation of network", true).Error())
		}
		out, _ := json.Marshal(network)
		fmt.Println(string(out))

		return nil
	},
}
