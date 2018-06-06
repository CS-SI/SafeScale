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
	"github.com/CS-SI/SafeScale/providers/api"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/urfave/cli"
)

//ContainerCmd container command
var ContainerCmd = cli.Command{
	Name:  "container",
	Usage: "container COMMAND",
	Subcommands: []cli.Command{
		containerList,
		containerCreate,
		containerDelete,
		containerInspect,
		containerMount,
		containerUmount,
	},
}

var containerList = cli.Command{
	Name:  "list",
	Usage: "List containers",
	Action: func(c *cli.Context) error {
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		resp, err := service.List(ctx, &google_protobuf.Empty{})
		if err != nil {
			return fmt.Errorf("Could not list containers: %v", err)
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}

var containerCreate = cli.Command{
	Name:      "create",
	Usage:     "Creates a container",
	ArgsUsage: "<Container_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Container_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		_, err := service.Create(ctx, &pb.Container{Name: c.Args().Get(0)})
		if err != nil {
			return fmt.Errorf("Could not create container '%s': %v", c.Args().Get(0), err)
		}

		return nil
	},
}

var containerDelete = cli.Command{
	Name:      "delete",
	Usage:     "Delete a container",
	ArgsUsage: "<Container_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Container_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		_, err := service.Delete(ctx, &pb.Container{Name: c.Args().Get(0)})
		if err != nil {
			return fmt.Errorf("Could not delete container '%s': %v", c.Args().Get(0), err)
		}

		return nil
	},
}

var containerInspect = cli.Command{
	Name:      "inspect",
	Usage:     "Inspect a container",
	ArgsUsage: "<Container_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Container_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		resp, err := service.Inspect(ctx, &pb.Container{Name: c.Args().Get(0)})
		if err != nil {
			return fmt.Errorf("Could not inspect container '%s': %v", c.Args().Get(0), err)
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}

var containerMount = cli.Command{
	Name:      "mount",
	Usage:     "Mount a container on the filesytem of a VM",
	ArgsUsage: "<Container_name> <VM_name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: api.DefaultContainerMountPoint,
			Usage: "Mount point of the container",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Container_name> and/or <VM_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container and VM name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxVM)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		_, err := service.Mount(ctx, &pb.ContainerMountingPoint{
			Container: c.Args().Get(0),
			VM: &pb.Reference{
				Name: c.Args().Get(1),
			},
			Path: c.String("path"),
		})
		if err != nil {
			return fmt.Errorf("Could not mount container '%s': %v\n", c.Args().Get(0), err)
		}
		fmt.Printf("Container '%s' mounted on '%s' on VM '%s'\n", c.Args().Get(0), c.String("path"), c.Args().Get(1))
		return nil
	},
}

var containerUmount = cli.Command{
	Name:      "umount",
	Usage:     "UMount a container from the filesytem of a VM",
	ArgsUsage: "<Container_name> <VM_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Container_name> and/or <VM_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container and VM name required")
		}
		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewContainerServiceClient(conn)

		_, err := service.UMount(ctx, &pb.ContainerMountingPoint{
			Container: c.Args().Get(0),
			VM: &pb.Reference{
				Name: c.Args().Get(1),
			},
		})
		if err != nil {
			return fmt.Errorf("Could not umount container '%s': %v\n", c.Args().Get(0), err)
		}
		fmt.Printf("Container '%s' umounted from VM '%s'\n", c.Args().Get(0), c.Args().Get(1))
		return nil
	},
}
