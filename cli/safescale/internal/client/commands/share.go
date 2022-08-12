//go:build fixme
// +build fixme

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
	"strings"
	"sync/atomic"

	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/urfave/cli"
)

var shareCmdName = "share"

// ShareCommands share command
func ShareCommands() *cobra.Command {
	out := &cobra.Command{
		Use:    "share",
		Aliases: []string{"nas"},
		Short:   "share COMMAND",
	}
	out.AddCommand(
		shareCreateCommand(),
		shareDeleteCommand(),
		shareMountCommand(),
		shareUnmountCommand(),
		shareListCommand(),
		shareInspectCommand(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

func shareCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "create",
		Aliases:   []string{"new"},
		Short:     "Create a nfs server on a host and exports a directory",
		// ArgsUsage: "<Share_name> <Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Nas_name> and/or <Host_name>."))
			}

			clientSession, xerr := cmdline.New(c.Flags().GetString("server"))
			if xerr != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
			}

			shareName := c.Args().Get(0)
			def := protocol.ShareDefinition{
				Name: shareName,
				Host: &protocol.Reference{Name: c.Args().Get(1)},
				Path: c.Flags().GetString("path"),
				Options: &protocol.NFSExportOptions{
					ReadOnly:     c.Flags().GetBool("readonly"),
					RootSquash:   c.Flags().GetBool("rootsquash"),
					Secure:       c.Flags().GetBool("secure"),
					Async:        c.Flags().GetBool("async"),
					NoHide:       c.Flags().GetBool("nohide"),
					CrossMount:   c.Flags().GetBool("crossmount"),
					SubtreeCheck: c.Flags().GetBool("subtreecheck"),
				},
				SecurityModes: c.Flags().GetStringSlice("securityModes"),
			}

			err := ClientSession.Share.Create(&def, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(cmdline.DecorateTimeoutError(err, "creation of share", true).Error()))
			}
			return clitools.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.String("path", abstract.DefaultShareExportedPath, "Path to be exported")
	flags.Bool("readonly", false, "Disallow write requests on this NFS volume")
	flags.Bool"rootsquash", false, "Map requests from uid/gid 0 to the anonymous uid/gid")
	flags.Bool("secure", false, "Requires that requests originate on an Internet port less than IPPORT_RESERVED (1024).")
	flags.Bool("async", false, "This option allows the NFS server to violate the NFS protocol and reply to requests before any changes made by that request have been committed to stable storage")
	flags.Bool("nohide", false, "Enable exports of volumes mounted in the share export path")
	flags.Bool("crossmount", false, "Similar to nohide but it makes it possible for clients to move from the filesystem marked with crossmnt to exported filesystems mounted on it")
	flags.Bool("subtreecheck", false, "Enable subtree checking")
	flags.StringSlice("securityModes", nil, "{sys(the default, no security), krb5(authentication only), krb5i(integrity protection), and krb5p(privacy protection)}")

	return out
}

func shareDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "delete",
		Aliases:   []string{"rm", "remove"},
		Short:     "Remove a share",
		// ArgsUsage: "<Share_name> [<Share_name>...]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) < 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Share_name>."))
			}

			var (
				shareList  []string
				errMessage atomic.Value
			)
			errMessage.Store("")

			shareList = append(shareList, args[0])
			shareList = append(shareList, args[1:]...)

			clientSession, xerr := cmdline.New(c.Flags().GetString("server"))
			if xerr != nil {
				return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
			}

			if err := ClientSession.Share.Delete(shareList, 0); err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of share", false).Error())))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

func shareListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:    "list",
		Aliases: []string{"ls"},
		Short:   "List all created shared",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Name(), strings.Join(args, ", "))

			list, err := ClientSession.Share.List(0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(cmdline.DecorateTimeoutError(err, "list of shares", false).Error()))
			}
			return clitools.SuccessResponse(list.ShareList)
		},
	}
	return out
}

func shareMountCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "mount",
		Short:     "Mount an exported nfs directory on a host",
		// ArgsUsage: "SHARE_REF HOST_REF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Nas_name> and/or <Host_name>."))
			}

			shareName := args[0]
			hostName := args[1]
			path := c.Flags().GetString("path")
			def := protocol.ShareMountDefinition{
				Host:      &protocol.Reference{Name: hostName},
				Share:     &protocol.Reference{Name: shareName},
				Path:      path,
				Type:      "nfs",
				WithCache: c.Flags().GetBool("ac"),
			}
			err := ClientSession.Share.Mount(&def, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(cmdline.DecorateTimeoutError(err, "mount of nas", true).Error()))
			}
			return clitools.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.String("path", abstract.DefaultShareMountPath, "Path to be mounted")
	flags.Bool("ac", false, "Disable cache coherence to improve performances")

	return out
}

func shareUnmountCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "umount",
		Aliases:   []string{"unmount"},
		Short:     "Unmount a Share from a host",
		// ArgsUsage: "SHARE_REF HOST_REF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments SHARE_REF and/or HOST_REF."))
			}

			shareName := c.Args().Get(0)
			hostName := c.Args().Get(1)
			def := protocol.ShareMountDefinition{
				Host:  &protocol.Reference{Name: hostName},
				Share: &protocol.Reference{Name: shareName},
			}
			err := ClientSession.Share.Unmount(&def, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(cmdline.DecorateTimeoutError(err, "unmount of share", true).Error()))
			}
			return clitools.SuccessResponse(nil)
		},
	}
	return out
}

func shareInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:      "inspect",
		Aliases:   []string{"show"},
		Short:     "inspect the Share information and clients connected to it",
		// ArgsUsage: "SHARE_REF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SHARE_REF."))
			}

			list, err := ClientSession.Share.Inspect(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(cmdline.DecorateTimeoutError(err, "inspection of share", false).Error()))
			}
			return clitools.SuccessResponse(list)
		},
	}
	return out
}
