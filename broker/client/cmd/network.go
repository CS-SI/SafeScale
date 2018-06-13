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
	utils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/urfave/cli"
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
	Name:  "list",
	Usage: "List existing Networks (created by SafeScale)",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "List all Networks on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		networkService := pb.NewNetworkServiceClient(conn)
		networks, err := networkService.List(ctx, &pb.NWListRequest{
			All: c.Bool("all"),
		})
		if err != nil {
			return fmt.Errorf("Could not get network list: %v", err)
		}
		out, _ := json.Marshal(networks.GetNetworks())
		fmt.Println(string(out))

		return nil
	},
}

var networkDelete = cli.Command{
	Name:      "delete",
	Usage:     "delete NETWORK",
	ArgsUsage: "<network_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <network_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Network name required")
		}

		// Network
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxVM)
		defer cancel()
		networkService := pb.NewNetworkServiceClient(conn)
		_, err := networkService.Delete(ctx, &pb.Reference{Name: c.Args().First(), TenantID: "TestOvh"})
		if err != nil {
			return fmt.Errorf("Could not delete network %s: %v", c.Args().First(), err)
		}
		fmt.Println(fmt.Sprintf("Network '%s' deleted", c.Args().First()))

		return nil
	},
}

var networkInspect = cli.Command{
	Name:      "inspect",
	Usage:     "inspect NETWORK",
	ArgsUsage: "<network_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <network_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Network name required")
		}

		// Network
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		networkService := pb.NewNetworkServiceClient(conn)
		network, err := networkService.Inspect(ctx, &pb.Reference{Name: c.Args().First(), TenantID: "TestOvh"})
		if err != nil {
			return fmt.Errorf("Could not inspect network %s: %v", c.Args().First(), err)
		}
		out, _ := json.Marshal(network)
		fmt.Println(string(out))

		return nil
	},
}

var networkCreate = cli.Command{
	Name:      "create",
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
			Value: 100,
			Usage: "Disk space for the gateway",
		},
		cli.StringFlag{
			Name:  "os",
			Value: "Ubuntu 16.04",
			Usage: "Image name for the gateway",
		}},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <network_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Network name reqired")
		}
		// Network
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxVM)
		defer cancel()
		networkService := pb.NewNetworkServiceClient(conn)
		netdef := &pb.NetworkDefinition{
			CIDR: c.String("cidr"),
			Name: c.Args().Get(0),
			Gateway: &pb.GatewayDefinition{
				CPU:  int32(c.Int("cpu")),
				Disk: int32(c.Int("disk")),
				RAM:  float32(c.Float64("ram")),
				// CPUFrequency: ??,
				ImageID: c.String("os"),
			},
		}
		network, err := networkService.Create(ctx, netdef)
		if err != nil {
			return fmt.Errorf("Could not get network list: %v", err)
		}
		out, _ := json.Marshal(network)
		fmt.Println(string(out))

		return nil
	},
}
