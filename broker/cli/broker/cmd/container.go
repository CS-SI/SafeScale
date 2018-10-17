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

	"github.com/CS-SI/SafeScale/broker/client"

	"github.com/CS-SI/SafeScale/providers/api"

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
		containerUnmount,
	},
}

var containerList = cli.Command{
	Name:  "list",
	Usage: "List containers",
	Action: func(c *cli.Context) error {
		resp, err := client.New().Container.List(0)
		if err != nil {
			return fmt.Errorf("Error response from daemon: %v", client.DecorateError(err, "list of containers", false))
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
		err := client.New().Container.Create(c.Args().Get(0), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon: %v", client.DecorateError(err, "creation of container", true))
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
		err := client.New().Container.Delete(c.Args().Get(0), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon: %v", client.DecorateError(err, "deletion of container", true))
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
		resp, err := client.New().Container.Inspect(c.Args().Get(0), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon: %v", client.DecorateError(err, "inspection of container", false))
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	},
}

var containerMount = cli.Command{
	Name:      "mount",
	Usage:     "Mount a container on the filesytem of an host",
	ArgsUsage: "<Container_name> <Host_name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: api.DefaultContainerMountPoint,
			Usage: "Mount point of the container",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Container_name> and/or <Host_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container and Host name required")
		}
		err := client.New().Container.Mount(c.Args().Get(0), c.Args().Get(1), c.String("path"), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon: %v", client.DecorateError(err, "mount of container", true))
		}
		fmt.Printf("Container '%s' mounted on '%s' on host '%s'\n", c.Args().Get(0), c.String("path"), c.Args().Get(1))
		return nil
	},
}

var containerUnmount = cli.Command{
	Name:      "umount",
	Usage:     "Unmount a container from the filesytem of an host",
	ArgsUsage: "<Container_name> <Host_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Container_name> and/or <Host_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Container and Host name required")
		}
		err := client.New().Container.Unmount(c.Args().Get(0), c.Args().Get(1), client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("Error response from daemon: %v", client.DecorateError(err, "unmount of container", true))
		}
		fmt.Printf("Container '%s' unmounted from host '%s'\n", c.Args().Get(0), c.Args().Get(1))
		return nil
	},
}
