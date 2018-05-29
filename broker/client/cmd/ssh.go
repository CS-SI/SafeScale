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
	"fmt"
	"os"

	pb "github.com/CS-SI/SafeScale/broker"
	conv "github.com/CS-SI/SafeScale/broker/utils"
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
	Usage:     "Run a command on the VM",
	ArgsUsage: "<VM_name|VM_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "c",
			Usage: "Command to execute",
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
		ctx, cancel := utils.GetContext(utils.TimeoutCtxDefault)
		defer cancel()
		service := pb.NewSshServiceClient(conn)

		resp, err := service.Run(ctx, &pb.SshCommand{
			VM:      &pb.Reference{Name: c.Args().Get(0)},
			Command: c.String("c"),
		})

		// TODO output result to stdout
		if err != nil {
			return fmt.Errorf("Could not execute ssh command: %v", err)
		}
		fmt.Print(fmt.Sprintf(resp.GetOutput()))
		fmt.Fprint(os.Stderr, fmt.Sprintf(resp.GetErr()))
		// fmt.Println(fmt.Sprintf(string(resp.GetStatus())))

		return nil
	},
}

var sshCopy = cli.Command{
	Name:      "copy",
	Usage:     "Copy a local file/directory to a VM or copy from VM to local",
	ArgsUsage: "from to  Ex: /my/local/file.txt vm1:/remote/path/",
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			fmt.Println("2 arguments (from and to) are required")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("2 arguments (from and to) are required")
		}

		conn := utils.GetConnection()
		defer conn.Close()
		ctx, cancel := utils.GetContext(utils.TimeoutCtxVM)
		defer cancel()
		service := pb.NewSshServiceClient(conn)

		_, err := service.Copy(ctx, &pb.SshCopyCommand{
			Source:      c.Args().Get(0),
			Destination: c.Args().Get(1),
		})
		if err != nil {
			return fmt.Errorf("Could not copy %s to %s: %v", c.Args().Get(0), c.Args().Get(1), err)
		}
		fmt.Println(fmt.Sprintf("Copy of '%s' to '%s' done", c.Args().Get(0), c.Args().Get(1)))

		return nil
	},
}

var sshConnect = cli.Command{
	Name:      "connect",
	Usage:     "Connect to the VM with interactive shell",
	ArgsUsage: "<VM_name|VM_ID>",
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

		sshConfig, err := service.SSH(ctx, &pb.Reference{
			Name: c.Args().Get(0),
		})
		if err != nil {
			return fmt.Errorf("Could not connect to %s: %v", c.Args().Get(0), err)
		}

		sshCfg := conv.ToAPISshConfig(sshConfig)

		return sshCfg.Enter()
	},
}
