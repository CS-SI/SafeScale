package cmd
/*
* Copyright 2015-2018, CS Systemes d'Information, http://www.c-s.fr
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

import (
	"encoding/json"
	"fmt"

	pb "github.com/SafeScale/broker"
	utils "github.com/SafeScale/broker/utils"
	"github.com/urfave/cli"
)

// VMCmd command
var VMCmd = cli.Command{
	Name:  "vm",
	Usage: "vm COMMAND",
	Subcommands: []cli.Command{
		vmList,
		vmCreate,
		vmDelete,
		vmInspect,
		vmSsh,
	},
}

var vmList = cli.Command{
	Name:  "list",
	Usage: "List available VMs (created by SafeScale)",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "List all VMs on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		vms, err := service.List(ctx, &pb.VMListRequest{
			All: c.Bool("all"),
		})
		if err != nil {
			return fmt.Errorf("Could not get vm list: %v", err)
		}
		out, _ := json.Marshal(vms.GetVMs())
		fmt.Println(string(out))

		return nil
	},
}

var vmInspect = cli.Command{
	Name:      "inspect",
	Usage:     "inspect VM",
	ArgsUsage: "<VM_name|VM_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <VM_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("VM name or ID required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		resp, err := service.Inspect(ctx, &pb.Reference{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not inspect vm '%s': %v", c.Args().First(), err)
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var vmCreate = cli.Command{
	Name:      "create",
	Usage:     "create a new VM",
	ArgsUsage: "<VM_name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "net",
			Usage: "Name or ID of the network to put the VM on",
		},
		cli.IntFlag{
			Name:  "cpu",
			Value: 1,
			Usage: "Number of CPU for the VM",
		},
		cli.Float64Flag{
			Name:  "ram",
			Value: 1,
			Usage: "RAM for the VM",
		},
		cli.IntFlag{
			Name:  "disk",
			Value: 100,
			Usage: "Disk space for the VM",
		},
		cli.StringFlag{
			Name:  "os",
			Value: "Ubuntu 16.04",
			Usage: "Image name for the VM",
		},
		cli.BoolFlag{
			Name:  "private",
			Usage: "Create with no public IP",
		},
		cli.BoolFlag{
			Name:   "gpu",
			Usage:  "With GPU",
			Hidden: true,
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <VM_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("VM name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxVM)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		resp, err := service.Create(ctx, &pb.VMDefinition{
			Name:      c.Args().First(),
			CPUNumber: int32(c.Int("cpu")),
			Disk:      int32(c.Float64("disk")),
			ImageID:   c.String("os"),
			Network:   c.String("net"),
			Public:    !c.Bool("private"),
			RAM:       float32(c.Float64("ram")),
		})
		if err != nil {
			return fmt.Errorf("Could not create vm '%s': %v", c.Args().First(), err)
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))

		return nil
	},
}

var vmDelete = cli.Command{
	Name:      "delete",
	Usage:     "Delete VM",
	ArgsUsage: "<VM_name|VM_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <VM_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("VM name or ID required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		_, err := service.Delete(ctx, &pb.Reference{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not delete vm '%s': %v", c.Args().First(), err)
		}
		fmt.Printf("VM '%s' deleted\n", c.Args().First())
		return nil
	},
}

var vmSsh = cli.Command{
	Name:      "ssh",
	Usage:     "Get ssh config to connect to VM",
	ArgsUsage: "<VM_name|VM_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <VM_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("VM name or ID required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewVMServiceClient(conn)
		resp, err := service.SSH(ctx, &pb.Reference{Name: c.Args().First()})
		if err != nil {
			return fmt.Errorf("Could not get ssh config for vm '%s': %v", c.Args().First(), err)
		}
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}
