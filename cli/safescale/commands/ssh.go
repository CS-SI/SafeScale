/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/ExitCode"
)

// SSHCmd ssh command
var SSHCmd = cli.Command{
	Name:  "ssh",
	Usage: "ssh COMMAND",
	Subcommands: []cli.Command{
		sshRun,
		sshCopy,
		sshConnect,
		sshTunnel,
		sshClose,
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
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		timeout := utils.GetHostTimeout()
		if c.IsSet("timeout") {
			timeout = time.Duration(c.Float64("timeout")) * time.Minute
		}
		retcode, stdout, stderr, err := client.New().Ssh.Run(c.Args().Get(0), c.String("c"), utils.GetConnectionTimeout(), timeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh run", false).Error())))
		}
		if retcode != 0 {
			fmt.Printf(stderr)
			return cli.NewExitError(stderr, retcode)
		}
		fmt.Printf(stdout)
		return nil
	},
}

func normalizeFileName(fileName string) string {
	absPath, _ := filepath.Abs(fileName)
	if _, err := os.Stat(absPath); err != nil {
		return fileName
	}
	return absPath
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
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("2 arguments (from and to) are required."))
		}

		timeout := utils.GetHostTimeout()
		if c.IsSet("timeout") {
			timeout = time.Duration(c.Float64("timeout")) * time.Minute
		}
		retcode, _, _, err := client.New().Ssh.Copy(normalizeFileName(c.Args().Get(0)), normalizeFileName(c.Args().Get(1)), utils.GetConnectionTimeout(), timeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh copy", true).Error())))
		}
		if retcode != 0 {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(ExitCode.Run, fmt.Sprintf("copy failed: retcode=%d (%s)", retcode, system.SSHErrorString(retcode))))
		}
		return clitools.SuccessResponse(nil)
	},
}

var sshConnect = cli.Command{
	Name:      "connect",
	Usage:     "Connect to the host with interactive shell",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("missing mandatory argument <Host_name>")
		}
		err := client.New().Ssh.Connect(c.Args().Get(0), 0)
		if err != nil {
			return clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh connect", false).Error()))
		}
		return nil
	},
}

var sshTunnel = cli.Command{
	Name:      "tunnel",
	Usage:     "Create a ssh tunnel between admin host and a host in the cloud",
	ArgsUsage: "<Host_name|Host_ID --local local_port  --remote remote_port>",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "local",
			Value: 8080,
			Usage: "local tunnel's port, if not set all",
		},
		cli.IntFlag{
			Name:  "remote",
			Value: 8080,
			Usage: "remote tunnel's port, if not set all",
		},
		cli.StringFlag{
			Name:  "timeout",
			Value: "1",
			Usage: "timeout in minutes",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		localPort := c.Int("local")
		if 0 > localPort || localPort > 65535 {
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("local port value is wrong, %d is not a valid port\n", localPort)))
		}

		remotePort := c.Int("remote")
		if 0 > localPort || localPort > 65535 {
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("remote port value is wrong, %d is not a valid port\n", remotePort)))
		}

		timeout := time.Duration(c.Float64("timeout")) * time.Minute

		//c.GlobalInt("port") is the grpc port aka. 50051
		err := client.New().Ssh.CreateTunnel(c.Args().Get(0), localPort, remotePort, timeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh tunnel", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var sshClose = cli.Command{
	Name:      "close",
	Usage:     "Close one or several ssh tunnel",
	ArgsUsage: "<Host_name|Host_ID> --local local_port --remote remote_port",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "local",
			Value: ".*",
			Usage: "local tunnel's port, if not set all",
		},
		cli.StringFlag{
			Name:  "remote",
			Value: ".*",
			Usage: "remote tunnel's port, if not set all",
		},
		cli.StringFlag{
			Name:  "timeout",
			Value: "1",
			Usage: "timeout in minutes",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		strLocalPort := c.String("local")
		if c.IsSet("local") {
			localPort, err := strconv.Atoi(strLocalPort)
			if err != nil || 0 > localPort || localPort > 65535 {
				return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("local port value is wrong, %d is not a valid port\n", localPort)))
			}
		}
		strRemotePort := c.String("remote")
		if c.IsSet("remote") {
			remotePort, err := strconv.Atoi(strRemotePort)
			if err != nil || 0 > remotePort || remotePort > 65535 {
				return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("remote port value is wrong, %d is not a valid port\n", remotePort)))
			}
		}

		timeout := time.Duration(c.Float64("timeout")) * time.Minute
		err := client.New().Ssh.CloseTunnels(c.Args().Get(0), strLocalPort, strRemotePort, timeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh close", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
