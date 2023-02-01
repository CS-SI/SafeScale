/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/client"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

var sshCmdName = "ssh"

// SSHCommand ssh command
var SSHCommand = cli.Command{
	Name:  "ssh",
	Usage: "ssh COMMAND",
	Subcommands: cli.Commands{
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
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		var timeout time.Duration
		if c.IsSet("timeout") {
			timeout = time.Duration(c.Float64("timeout")) * time.Minute
		} else {
			timeout = 0
		}

		retcode, _, _, err := ClientSession.SSH.Run(c.Args().Get(0), c.String("c"), outputs.DISPLAY, temporal.ConnectionTimeout(), timeout)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh run", false).Error())))
		}
		if retcode != 0 {
			return cli.NewExitError("", retcode)
		}
		return nil
	},
}

func normalizeExistingFileName(fileName string) (string, error) {
	if strings.Contains(fileName, ":") { // it's a remote reference, no need to normalize
		return fileName, nil
	}

	absPath, err := filepath.Abs(fileName)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(absPath); err != nil {
		return "", err
	}

	return absPath, nil
}

func normalizeFileName(fileName string) (string, error) {
	if strings.Contains(fileName, ":") { // it's a remote reference, no need to normalize
		return fileName, nil
	}

	absPath, err := filepath.Abs(fileName)
	if err != nil {
		return "", err
	}

	return absPath, nil
}

var sshCopy = cli.Command{
	Name:      "copy",
	Usage:     "Copy a local file/directory to a host or copy from host to local",
	ArgsUsage: "from to  Ex: /my/local/file.txt host1:/remote/path/",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "timeout",
			Value: "5",
			Usage: "timeout in minutes",
		}},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdName, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("2 arguments (from and to) are required."))
		}

		var timeout time.Duration
		if c.IsSet("timeout") {
			timeout = time.Duration(c.Float64("timeout")) * time.Minute
		} else {
			timeout = 0
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Copying files"
			pb := progressbar.NewOptions(-1, progressbar.OptionFullWidth(), progressbar.OptionClearOnFinish(), progressbar.OptionSetDescription(description))
			go func() {
				for {
					if pb.IsFinished() {
						return
					}
					err := pb.Add(1)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()

			defer func() {
				_ = pb.Finish()
			}()
		}

		first, err := normalizeExistingFileName(c.Args().Get(0))
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh copy", true).Error())))
		}

		// the second file name (destination) might not exist
		second, err := normalizeFileName(c.Args().Get(1))
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh copy", true).Error())))
		}

		retcode, _, _, err := ClientSession.SSH.Copy(first, second, temporal.ConnectionTimeout(), timeout)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh copy", true).Error())))
		}
		if retcode != 0 {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, fmt.Sprintf("copy failed: retcode=%d", retcode)))
		}
		return clitools.SuccessResponse(nil)
	},
}

var sshConnect = cli.Command{
	Name:      "connect",
	Usage:     "Connect to the host with interactive shell",
	ArgsUsage: "<Host_name|Host_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "username, u",
			Value: "",
			Usage: "Username to connect to",
		},
		cli.StringFlag{
			Name:  "shell, s",
			Value: "bash",
			Usage: "Shell to use (default: bash)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return fmt.Errorf("missing mandatory argument <Host_name>")
		}

		// Check host status 1st
		resp, err := ClientSession.Host.GetStatus(c.Args().Get(0), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "status of host", false).Error())))
		}

		converted := converters.HostStateFromProtocolToEnum(resp.Status)
		if converted != hoststate.Started {
			return clitools.FailureResponse(clitools.ExitOnRPC(fmt.Sprintf("Host %s is not in 'Started' state, it's '%s'", c.Args().Get(0), converted.String())))
		}

		var (
			username, shell string
		)
		if c.IsSet("username") {
			username = c.String("username")
		}
		if c.IsSet("shell") {
			shell = c.String("shell")
		}
		err = ClientSession.SSH.Connect(c.Args().Get(0), username, shell, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh connect", false).Error()))
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
			Name:  "timeout, t",
			Value: "1",
			Usage: "timeout in minutes",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		localPort := c.Int("local")
		if 0 > localPort || localPort > 65535 {
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("local port value is wrong, %d is not a valid port", localPort)))
		}

		remotePort := c.Int("remote")
		if 0 > localPort || localPort > 65535 {
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("remote port value is wrong, %d is not a valid port", remotePort)))
		}

		timeout := time.Duration(c.Float64("timeout")) * time.Minute

		// c.GlobalInt("port") is the grpc port aka. 50051
		err := ClientSession.SSH.CreateTunnel(c.Args().Get(0), localPort, remotePort, timeout)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh tunnel", false).Error())))
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
			Name:  "timeout, t",
			Value: "1",
			Usage: "timeout in minutes",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
		}

		strLocalPort := c.String("local")
		if c.IsSet("local") {
			localPort, err := strconv.Atoi(strLocalPort)
			if err != nil || 0 > localPort || localPort > 65535 {
				return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("local port value is wrong, %d is not a valid port", localPort)))
			}
		}
		strRemotePort := c.String("remote")
		if c.IsSet("remote") {
			remotePort, err := strconv.Atoi(strRemotePort)
			if err != nil || 0 > remotePort || remotePort > 65535 {
				return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("remote port value is wrong, %d is not a valid port", remotePort)))
			}
		}

		timeout := time.Duration(c.Float64("timeout")) * time.Minute
		err := ClientSession.SSH.CloseTunnels(c.Args().Get(0), strLocalPort, strRemotePort, timeout)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "ssh close", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
