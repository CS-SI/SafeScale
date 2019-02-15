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
	"sync"

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
		cli.BoolFlag{
			Name:  "readonly",
			Usage: "Disallow write requests on this NFS volume",
		},
		cli.BoolFlag{
			Name:  "rootsquash",
			Usage: "Map requests from uid/gid 0 to the anonymous uid/gid",
		},
		cli.BoolFlag{
			Name:  "secure",
			Usage: "Requires that requests originate on an Internet port less than IPPORT_RESERVED (1024).",
		},
		cli.BoolFlag{
			Name:  "async",
			Usage: "This option allows the NFS server to violate the NFS protocol and reply to requests before any changes made by that request have been committed to stable storage",
		},
		cli.BoolFlag{
			Name:  "nohide",
			Usage: "Enable exports of volumes mounted in the share export path",
		},
		cli.BoolFlag{
			Name:  "crossmount",
			Usage: "Similar to nohide but it makes it possible for clients to move from the filesystem marked with crossmnt to exported filesystems mounted on it",
		},
		cli.BoolFlag{
			Name:  "subtreecheck",
			Usage: "Enable subtree checking",
		},
		cli.StringSliceFlag{
			Name:  "securityModes",
			Usage: "{sys(the default--no cryptographic security), krb5(authentication only), krb5i(integrity protection), and krb5p(privacy protection)}",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("Missing mandatory argument <Nas_name> and/or <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		shareName := c.Args().Get(0)
		def := pb.ShareDefinition{
			Name: shareName,
			Host: &pb.Reference{Name: c.Args().Get(1)},
			Path: c.String("path"),
			Options: &pb.ExportOptions{
				ReadOnly:     c.Bool("readonly"),
				RootSquash:   c.Bool("rootsquash"),
				Secure:       c.Bool("secure"),
				Async:        c.Bool("async"),
				NoHide:       c.Bool("nohide"),
				CrossMount:   c.Bool("crossmount"),
				SubtreeCheck: c.Bool("subtreecheck"),
			},
			SecurityModes: c.StringSlice("securityModes"),
		}
		err := client.New().Share.Create(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "creation of share", true).Error())
		}

		fmt.Printf("Share '%s' successfully created.\n", shareName)
		return nil
	},
}

var shareDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Delete a share",
	ArgsUsage: "<Share_name> [<Share_name>...]",
	Action: func(c *cli.Context) error {
		if c.NArg() < 1 {
			fmt.Println("Missing mandatory argument <Share_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}

		var (
			wg        sync.WaitGroup
			errs      int
			shareList []string
		)
		shareList = append(shareList, c.Args().First())
		shareList = append(shareList, c.Args().Tail()...)

		shareDeleter := func(aname string) {
			defer wg.Done()
			err := client.New().Share.Delete(aname, client.DefaultExecutionTimeout)
			if err != nil {
				fmt.Println(clitools.Capitalize(err.Error()))
				errs++
			} else {
				fmt.Printf("Share '%s' successfully deleted.\n", aname)
			}
		}

		wg.Add(len(shareList))
		for _, target := range shareList {
			go shareDeleter(target)
		}
		wg.Wait()

		if errs > 0 {
			return clitools.ExitOnRPC("")
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
		cli.BoolFlag{
			Name:  "ac",
			Usage: "Disable chache coherence to improve performences",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			_, _ = fmt.Fprintln(os.Stderr, "Missing mandatory argument <Nas_name> and/or <Host_name>")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		shareName := c.Args().Get(0)
		hostName := c.Args().Get(1)
		path := c.String("path")
		def := pb.ShareMountDefinition{
			Host:      &pb.Reference{Name: hostName},
			Share:     &pb.Reference{Name: shareName},
			Path:      path,
			Type:      "nfs",
			WithCache: c.Bool("ac"),
		}
		err := client.New().Share.Mount(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "mount of nas", true).Error())
		}

		fmt.Printf("Share '%s' successfully mounted on '%s:%s'.\n", shareName, hostName, path)
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
		shareName := c.Args().Get(0)
		hostName := c.Args().Get(1)
		def := pb.ShareMountDefinition{
			Host:  &pb.Reference{Name: hostName},
			Share: &pb.Reference{Name: shareName},
		}
		err := client.New().Share.Unmount(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(client.DecorateError(err, "unmount of share", true).Error())
		}

		fmt.Printf("Share '%s' successfully unmounted from host '%s'\n", shareName, hostName)
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

		output := map[string]interface{}{
			"ID":   list.GetShare().GetID(),
			"Name": list.GetShare().GetName(),
			"Host": list.GetShare().GetHost().GetName(),
			"Path": list.GetShare().GetPath(),
			"Type": list.GetShare().GetType(),
		}

		mountsOutput := map[string]interface{}{}
		for _, i := range list.MountList {
			mountsOutput[i.GetHost().GetName()] = map[string]interface{}{
				// "ID":   i.GetShare.GetID(),
				// "Name": i.GetShare().GetName(),
				// "Host": i.GetHost().GetName(),
				"Path": i.GetPath(),
				// "Type": i.GetType(),
			}
		}

		output["mounts"] = mountsOutput

		out, _ := json.Marshal(output)
		fmt.Println(string(out))

		return nil
	},
}
