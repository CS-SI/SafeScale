/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

var sshCmdLabel = "ssh"

// SSHCommand ssh command
func SSHCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   sshCmdLabel,
		Short: "ssh COMMAND",
	}
	out.AddCommand(
		sshRunCommand(),
		sshCopyCommand(),
		sshConnectCommand(),
		sshTunnelCommand(),
		sshCloseCommand(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

func sshRunCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "run",
		Short: "Run a command on the host",
		// ArgsUsage: "<Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			var timeout time.Duration
			if c.Flags().Lookup("timeout") {
				timeout = time.Duration(c.Float64("timeout")) * time.Minute
			} else {
				timeout = temporal.HostOperationTimeout()
			}
			retcode, _, _, err := ClientSession.SSH.Run(c.Args().Get(0), c.Flags().GetString("c"), outputs.DISPLAY, temporal.ConnectionTimeout(), timeout)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "ssh run", false).Error())))
			}
			if retcode != 0 {
				return cli.Exit("", retcode)
			}
			return nil
		},
	}

	flags := out.Flags()
	flags.String("c", "", "Command to execute")
	flags.Uint("timeout", "5", "timeout in minutes")

	return out
}

func normalizeFileName(fileName string) string {
	absPath, _ := filepath.Abs(fileName)
	if _, err := os.Stat(absPath); err != nil {
		return fileName
	}
	return absPath
}

func sshCopyCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "copy",
		Short: "Copy a local file/directory to a host or copy from host to local",
		// ArgsUsage: "from to  Ex: /my/local/file.txt host1:/remote/path/",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("2 arguments (from and to) are required."))
			}

			var timeout time.Duration
			if c.Flags().Lookup("timeout") {
				timeout = time.Duration(c.Float64("timeout")) * time.Minute
			} else {
				timeout = temporal.HostOperationTimeout()
			}
			retcode, _, _, err := ClientSession.SSH.Copy(normalizeFileName(c.Args().Get(0)), normalizeFileName(c.Args().Get(1)), temporal.ConnectionTimeout(), timeout)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "ssh copy", true).Error())))
			}
			if retcode != 0 {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, fmt.Sprintf("copy failed: retcode=%d", retcode)))
			}
			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.Uint("timeout", 5, "timeout in minutes")

	return out
}

func sshConnectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "connect",
		Short: "Connect to the host with interactive shell",
		// ArgsUsage: "<Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return fmt.Errorf("missing mandatory argument <Host_name>")
			}

			// Check host status 1st
			resp, err := ClientSession.Host.GetStatus(c.Args().Get(0), 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "status of host", false).Error())))
			}
			converted := converters.HostStateFromProtocolToEnum(resp.Status)
			if converted != hoststate.Started {
				return cli.FailureResponse(cli.ExitOnRPC(fmt.Sprintf("Host %s is not in 'Started' state, it's '%s'", c.Args().Get(0), converted.String())))
			}

			var (
				username, shell string
			)
			if c.Flags().Lookup("username") {
				username = c.Flags().GetString("username")
			}
			if c.Flags().Lookup("shell") {
				shell = c.Flags().GetString("shell")
			}
			err = clientSession.SSH.Connect(c.Args().Get(0), username, shell, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "ssh connect", false).Error()))
			}
			return nil
		},
	}

	flags := out.Flags()
	flags.StringP("username", "u", "", "Username to connect to")
	flags.StringP("shell", "s", "bash", "Shell to use (default: bash)")

	return out
}

func sshTunnelCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "tunnel",
		Short: "Create a ssh tunnel between admin host and a host in the cloud",
		//  ArgsUsage: "<Host_name|Host_ID --local local_port  --remote remote_port>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			localPort := c.Flags().GetInt("local")
			if 0 > localPort || localPort > 65535 {
				return cli.FailureResponse(cli.ExitOnInvalidOption(fmt.Sprintf("local port value is wrong, %d is not a valid port", localPort)))
			}

			remotePort := c.Flags().GetInt("remote")
			if 0 > localPort || localPort > 65535 {
				return cli.FailureResponse(cli.ExitOnInvalidOption(fmt.Sprintf("remote port value is wrong, %d is not a valid port", remotePort)))
			}

			timeout := time.Duration(c.Float64("timeout")) * time.Minute

			// c.GlobalInt("port") is the grpc port aka. 50051
			err := ClientSession.SSH.CreateTunnel(c.Args().Get(0), localPort, remotePort, timeout)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "ssh tunnel", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.Uint16("local", 8080, "local tunnel's port, if not set all")
	flags.Uint16("remote", 8080, "remote tunnel's port, if not set all")
	flags.UintP("timeout", "t", 1, "timeout in minutes (default: 1)")

	return out
}

func sshCloseCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "close",
		Short: "Close one or several ssh tunnel",
		// ArgsUsage: "<Host_name|Host_ID> --local local_port --remote remote_port",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", sshCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Host_name>."))
			}

			strLocalPort := c.Flags().GetString("local")
			if c.Flags().Lookup("local") {
				localPort, err := strconv.Atoi(strLocalPort)
				if err != nil || 0 > localPort || localPort > 65535 {
					return cli.FailureResponse(cli.ExitOnInvalidOption(fmt.Sprintf("local port value is wrong, %d is not a valid port", localPort)))
				}
			}
			strRemotePort := c.Flags().GetString("remote")
			if c.Flags().Lookup("remote") {
				remotePort, err := strconv.Atoi(strRemotePort)
				if err != nil || 0 > remotePort || remotePort > 65535 {
					return cli.FailureResponse(cli.ExitOnInvalidOption(fmt.Sprintf("remote port value is wrong, %d is not a valid port", remotePort)))
				}
			}

			timeout := time.Duration(c.Float64("timeout")) * time.Minute
			err := ClientSession.SSH.CloseTunnels(c.Args().Get(0), strLocalPort, strRemotePort, timeout)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "ssh close", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.Uint16("local", 0, "local tunnel's port, if not set all")
	flags.Uint16("remote", 0, "remote tunnel's port, if not set all")
	flags.UintP("timeout", "t", 1, "timeout in minutes (default: 1)")

	return out
}
