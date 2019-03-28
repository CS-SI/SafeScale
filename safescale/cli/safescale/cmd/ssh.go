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

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/safescale/client"
	safescaleutils "github.com/CS-SI/SafeScale/safescale/utils"
	"github.com/CS-SI/SafeScale/utils"
	clitools "github.com/CS-SI/SafeScale/utils"
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
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			//_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>. For help --> safescale ssh run -h"))
		} else {
			timeout := safescaleutils.GetTimeoutCtxHost()
			if c.IsSet("timeout") {
				timeout = time.Duration(c.Float64("timeout")) * time.Minute
			}
			retcode, stdout, stderr, err := client.New().Ssh.Run(c.Args().Get(0), c.String("c"), client.DefaultConnectionTimeout, timeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh run", false).Error())))
			} else {
				if retcode != 0 {
					//msg := fmt.Sprintf("stdOut: %s ---- stdErr: %s", stdout, stderr)
					response.Failed(cli.NewExitError(stderr, retcode))
				} else {
					response.Succeeded(stdout)
				}
			}
		}

		return response.GetError()
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
		response := utils.NewCliResponse()

		if c.NArg() != 2 {
			//_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("2 arguments (from and to) are required. For help --> safescale ssh copy -h"))
		} else {
			timeout := safescaleutils.GetTimeoutCtxHost()
			if c.IsSet("timeout") {
				timeout = time.Duration(c.Float64("timeout")) * time.Minute
			}
			_, _, _, err := client.New().Ssh.Copy(normalizeFileName(c.Args().Get(0)), normalizeFileName(c.Args().Get(1)), client.DefaultConnectionTimeout, timeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh copy", true).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetError()
	},
}

var sshConnect = cli.Command{
	Name:      "connect",
	Usage:     "Connect to the host with interactive shell",
	ArgsUsage: "<Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			//_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>. For help --> safescale ssh connect -h"))
		} else {
			err := client.New().Ssh.Connect(c.Args().Get(0), 0)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh connect", false).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetError()
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
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			//_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>. For help --> safescale ssh close -h"))
		} else {
			localPort := c.Int("local")
			if 0 > localPort || localPort > 65535 {
				return response.Failed(clitools.ExitOnInvalidOption(fmt.Sprintf("local port value is wrong, %d is not a valid port\n", localPort)))
			}

			remotePort := c.Int("remote")
			if 0 > localPort || localPort > 65535 {
				return response.Failed(clitools.ExitOnInvalidOption(fmt.Sprintf("remote port value is wrong, %d is not a valid port\n", remotePort)))
			}

			timeout := time.Duration(c.Float64("timeout")) * time.Minute

			//c.GlobalInt("port") is the grpc port aka. 50051
			err := client.New().Ssh.CreateTunnel(c.Args().Get(0), localPort, remotePort, timeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh tunnel", false).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetError()
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
		response := utils.NewCliResponse()

		if c.NArg() != 1 {
			//_ = cli.ShowSubcommandHelp(c)
			response.Failed(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>. For help --> safescale ssh close -h"))
		} else {
			strLocalPort := c.String("local")
			if c.IsSet("local") {
				localPort, err := strconv.Atoi(strLocalPort)
				if err != nil || 0 > localPort || localPort > 65535 {
					return response.Failed(clitools.ExitOnInvalidOption(fmt.Sprintf("local port value is wrong, %d is not a valid port\n", localPort)))
				}
			}
			strRemotePort := c.String("remote")
			if c.IsSet("remote") {
				remotePort, err := strconv.Atoi(strRemotePort)
				if err != nil || 0 > remotePort || remotePort > 65535 {
					return response.Failed(clitools.ExitOnInvalidOption(fmt.Sprintf("remote port value is wrong, %d is not a valid port\n", remotePort)))
				}
			}

			timeout := time.Duration(c.Float64("timeout")) * time.Minute
			err := client.New().Ssh.CloseTunnels(c.Args().Get(0), strLocalPort, strRemotePort, timeout)
			if err != nil {
				response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "ssh close", false).Error())))
			} else {
				response.Succeeded(nil)
			}
		}

		return response.GetError()
	},
}
