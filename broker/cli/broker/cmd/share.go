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
	"os"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/client"
	"github.com/CS-SI/SafeScale/providers/model"
	clitools "github.com/CS-SI/SafeScale/utils"

	"github.com/urfave/cli"
)

// ShareCmd ssh command
var ShareCmd = cli.Command{
	Name:    "share",
	Aliases: []string{"nas"},
	Usage:   "share COMMAND",
	Subcommands: []cli.Command{
		shareCreate,
		shareDelete,
		shareMount,
		shareUnmount,
		shareList,
		shareInspect,
	},
}

var shareCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a nfs server on an host and exports a directory",
	ArgsUsage: "<Share_name> <Host_name|Host_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: model.DefaultShareExportedPath,
			Usage: "Path to be exported",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Nas_name> and/or <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		def := pb.ShareDefinition{
			Name: c.Args().Get(0),
			Host: &pb.Reference{Name: c.Args().Get(1)},
			Path: c.String("path"),
		}
		err := client.New().Share.Create(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "creation of share", true).Error())
		}

		fmt.Println("Share successfully created.")
		return nil
	},
}

var shareDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Delete a share from an host",
	ArgsUsage: "<Share_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() < 1 {
			fmt.Println("Missing mandatory argument <Share_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}

		var shareList []string
		shareList = append(shareList, c.Args().First())
		shareList = append(shareList, c.Args().Tail()...)

		err := client.New().Share.Delete(shareList, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "deletion of share", false).Error())
		}

		return nil
	},
}

var shareList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List all created shared",
	Action: func(c *cli.Context) error {
		list, err := client.New().Share.List(0)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "list of shares", false).Error())
		}
		var out []byte
		if len(list.ShareList) == 0 {
			out, _ = json.Marshal(nil)
		} else {
			var output []map[string]interface{}
			for _, i := range list.ShareList {
				output = append(output, map[string]interface{}{
					"ID":   i.GetID(),
					"Name": i.GetName(),
					"Host": i.GetHost().GetName(),
					"Path": i.GetPath(),
					"Type": i.GetType(),
				})
			}
			out, _ = json.Marshal(output)
		}
		fmt.Println(string(out))

		return nil
	},
}

var shareMount = cli.Command{
	Name:      "mount",
	Usage:     "Mount an exported nfs directory on an host",
	ArgsUsage: "<Share_name> <Host_name|Host_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: model.DefaultShareMountPath,
			Usage: "Path to be mounted",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Fprintln(os.Stderr, "Missing mandatory argument <Nas_name> and/or <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		def := pb.ShareMountDefinition{
			Host:  &pb.Reference{Name: c.Args().Get(1)},
			Share: &pb.Reference{Name: c.Args().Get(0)},
			Path:  c.String("path"),
			Type:  "nfs",
		}
		err := client.New().Share.Mount(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "mount of nas", true).Error())
		}
		return nil
	},
}

var shareUnmount = cli.Command{
	Name:      "umount",
	Aliases:   []string{"unmount"},
	Usage:     "Unmount a share from an host",
	ArgsUsage: "<Share_name> <Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Nas_name> and/or <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		def := pb.ShareMountDefinition{
			Host:  &pb.Reference{Name: c.Args().Get(1)},
			Share: &pb.Reference{Name: c.Args().Get(0)},
		}
		err := client.New().Share.Unmount(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "unmount of share", true).Error())
		}

		return nil
	},
}

var shareInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "List the share information and clients connected to it",
	ArgsUsage: "<Share_name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Share_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		list, err := client.New().Share.Inspect(c.Args().Get(0), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "inspection of share", false).Error())
		}
		var out []byte
		if len(list.ShareList) == 0 {
			out, _ = json.Marshal(nil)
		} else {
			var output []map[string]interface{}
			for _, i := range list.ShareList {
				output = append(output, map[string]interface{}{
					"ID":   i.GetID(),
					"Name": i.GetName(),
					"Host": i.GetHost().GetName(),
					"Path": i.GetPath(),
					"Type": i.GetType(),
				})
			}
			out, _ = json.Marshal(output)
		}
		fmt.Println(string(out))

		return nil
	},
}
