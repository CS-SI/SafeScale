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
	"github.com/CS-SI/SafeScale/providers/model"

	"github.com/urfave/cli"
)

//NasCmd ssh command
var NasCmd = cli.Command{
	Name:  "nas",
	Usage: "nas COMMAND",
	Subcommands: []cli.Command{
		nasCreate,
		nasDelete,
		nasMount,
		nasUnmount,
		nasList,
		nasInspect,
	},
}

var nasCreate = cli.Command{
	Name:      "create",
	Usage:     "Create a nfs server on an host and expose a directory",
	ArgsUsage: "<Nas_name> <Host_name|Host_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: model.DefaultNasExposedPath,
			Usage: "Path to be exported",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Nas_name> and/or <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Nas and Host name required")
		}
		def := pb.NasExportDefinition{
			Name: &pb.NasExportName{Name: c.Args().Get(0)},
			Host: &pb.Reference{Name: c.Args().Get(1)},
			Path: c.String("path"),
		}
		err := client.New().Nas.Create(def, client.DefaultExecutionTimeout)
		if err != nil {
			return client.DecorateError(err, "creation of nas", true)
		}

		return nil
	},
}

var nasDelete = cli.Command{
	Name:      "delete",
	Usage:     "Delete a nfs server on an host and expose a directory",
	ArgsUsage: "<Nas_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() < 1 {
			fmt.Println("Missing mandatory argument <Nas_name>")
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Nas name required")
		}

		var nasList []string
		nasList = append(nasList, c.Args().First())
		nasList = append(nasList, c.Args().Tail()...)

		_ = client.New().Nas.Delete(nasList, client.DefaultExecutionTimeout)

		return nil
	},
}

var nasList = cli.Command{
	Name:  "list",
	Usage: "List all created nas",
	Action: func(c *cli.Context) error {
		nases, err := client.New().Nas.List(0)
		if err != nil {
			return client.DecorateError(err, "list of nas", false)
		}
		out, _ := json.Marshal(nases)
		fmt.Println(string(out))

		return nil
	},
}

var nasMount = cli.Command{
	Name:      "mount",
	Usage:     "Mount an exported nfs directory on an host",
	ArgsUsage: "<Nas_name> <Host_name|Host_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: model.DefaultNasMountPath,
			Usage: "Path to be mounted",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Nas_name> and/or <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Nas and Host name required")
		}
		def := pb.NasMountDefinition{
			Host: &pb.Reference{Name: c.Args().Get(1)},
			Name: &pb.NasExportName{Name: c.Args().Get(1)},
			Path: c.String("path"),
			Type: "nfs",
		}
		err := client.New().Nas.Mount(def, client.DefaultExecutionTimeout)
		if err != nil {
			return client.DecorateError(err, "mount of nas", true)
		}
		return nil
	},
}

var nasUnmount = cli.Command{
	Name:      "umount",
	Usage:     "Unmount an exported nfs directory on an host",
	ArgsUsage: "<Nas_name> <Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Nas_name> and/or <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Nas and Host name required")
		}
		def := pb.NasMountDefinition{
			Host: &pb.Reference{Name: c.Args().Get(1)},
			Name: &pb.NasExportName{Name: c.Args().Get(0)},
		}
		err := client.New().Nas.Unmount(def, client.DefaultExecutionTimeout)
		if err != nil {
			return client.DecorateError(err, "unmount of nas", true)
		}

		return nil
	},
}

var nasInspect = cli.Command{
	Name:      "inspect",
	Usage:     "List the nfs server and all clients connected to it",
	ArgsUsage: "<Nas_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Nas_name>")
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Nas name required")
		}
		export, err := client.New().Nas.Inspect(c.Args().Get(0), client.DefaultExecutionTimeout)
		if err != nil {
			return client.DecorateError(err, "inspection of nas", false)
		}
		out, _ := json.Marshal(export)
		fmt.Println(string(out))

		return nil
	},
}
