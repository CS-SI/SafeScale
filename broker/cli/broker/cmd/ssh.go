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
	"fmt"
	"os"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/client"
	utils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/urfave/cli"
)

//SSHCmd ssh command
var SSHCmd = cli.Command{
	Name:  "ssh",
	Usage: "ssh COMMAND",
	Subcommands: []cli.Command{
		sshRun,
		sshCopy,
		sshConnect,
	},
}

var sshRun = cli.Command{
	Name:      "run",
	Usage:     "Run a command on the host",
	ArgsUsage: "<Host_name|Host_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "c",
			Usage: "Command to execute",
		},
		cli.StringFlag{
			Name:  "timeout",
			Value: "5",
			Usage: "timeout in minutes",
		}},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("host name required")
		}
		command := pb.SshCommand{
			Host:    &pb.Reference{Name: c.Args().Get(0)},
			Command: c.String("c"),
		}
		timeout := utils.TimeoutCtxHost
		if c.IsSet("timeout") {
			timeout = time.Duration(c.Float64("timeout")) * time.Minute
		}
		resp, err := client.New().Ssh.Run(command, timeout)
		if err != nil {
			return fmt.Errorf("Could not execute ssh command: %v", err)
		}

		fmt.Print(resp.GetOutputStd())
		fmt.Fprint(os.Stderr, resp.GetOutputErr())

		os.Exit(int(resp.GetStatus()))
		return nil
	},
}

var sshCopy = cli.Command{
	Name:      "copy",
	Usage:     "Copy a local file/directory to an host or copy from host to local",
	ArgsUsage: "from to  Ex: /my/local/file.txt host1:/remote/path/",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "timeout",
			Value: "5",
			Usage: "timeout in minutes",
		}},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("2 arguments (from and to) are required")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("2 arguments (from and to) are required")
		}
		command := pb.SshCopyCommand{
			Source:      c.Args().Get(0),
			Destination: c.Args().Get(1),
		}
		timeout := utils.TimeoutCtxHost
		if c.IsSet("timeout") {
			timeout = time.Duration(c.Float64("timeout")) * time.Minute
		}
		err := client.New().Ssh.Copy(command, timeout)
		if err != nil {
			return fmt.Errorf("Could not copy %s to %s: %v", c.Args().Get(0), c.Args().Get(1), err)
		}
		fmt.Printf("Copy of '%s' to '%s' done\n", c.Args().Get(0), c.Args().Get(1))
		return nil
	},
}

var sshConnect = cli.Command{
	Name:      "connect",
	Usage:     "Connect to the host with interactive shell",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <Host_name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("host name required")
		}
		return client.New().Ssh.Connect(c.Args().Get(0), 0)
	},
}
