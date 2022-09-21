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

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

var shareCmdName = "share"

// ShareCommands share command
func ShareCommands() *cobra.Command {
	out := &cobra.Command{
		Use:     "share",
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
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "Create a nfs server on a host and exports a directory",
		// ArgsUsage: "<Share_name> <Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Nas_name> and/or <Host_name>."))
			}

			path, err := c.Flags().GetString("path")
			if err != nil {
				return cli.FailureResponse(err)
			}

			readonly, err := c.Flags().GetBool("readonly")
			if err != nil {
				return cli.FailureResponse(err)
			}

			rootsquash, err := c.Flags().GetBool("rootsquash")
			if err != nil {
				return cli.FailureResponse(err)
			}

			secure, err := c.Flags().GetBool("secure")
			if err != nil {
				return cli.FailureResponse(err)
			}

			async, err := c.Flags().GetBool("async")
			if err != nil {
				return cli.FailureResponse(err)
			}

			nohide, err := c.Flags().GetBool("nohide")
			if err != nil {
				return cli.FailureResponse(err)
			}

			crossmount, err := c.Flags().GetBool("crossmount")
			if err != nil {
				return cli.FailureResponse(err)
			}

			subtreecheck, err := c.Flags().GetBool("subtreecheck")
			if err != nil {
				return cli.FailureResponse(err)
			}

			securityModes, err := c.Flags().GetStringSlice("securityModes")
			if err != nil {
				return cli.FailureResponse(err)
			}

			shareName := args[0]
			def := protocol.ShareCreateRequest{
				Name: shareName,
				Host: &protocol.Reference{Name: args[1]},
				Path: path,
				Options: &protocol.NFSExportOptions{
					ReadOnly:     readonly,
					RootSquash:   rootsquash,
					Secure:       secure,
					Async:        async,
					NoHide:       nohide,
					CrossMount:   crossmount,
					SubtreeCheck: subtreecheck,
				},
				SecurityModes: securityModes,
			}

			err = ClientSession.Share.Create(&def, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(cmdline.DecorateTimeoutError(err, "creation of share", true).Error()))
			}
			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.String("path", abstract.DefaultShareExportedPath, "Path to be exported")
	flags.Bool("readonly", false, "Disallow write requests on this NFS volume")
	flags.Bool("rootsquash", false, "Map requests from uid/gid 0 to the anonymous uid/gid")
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
		Use:     "delete",
		Aliases: []string{"rm", "remove"},
		Short:   "Remove a share",
		// ArgsUsage: "<Share_name> [<Share_name>...]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) < 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Share_name>."))
			}

			// var errMessage atomic.Value
			// errMessage.Store("")

			if err := ClientSession.Share.Delete(args, 0); err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of share", false).Error())))
			}

			return cli.SuccessResponse(nil)
		},
	}
	return out
}

func shareListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all created shared",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Name(), strings.Join(args, ", "))

			list, err := ClientSession.Share.List(0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(cmdline.DecorateTimeoutError(err, "list of shares", false).Error()))
			}
			return cli.SuccessResponse(list.ShareList)
		},
	}
	return out
}

func shareMountCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "mount",
		Short: "Mount an exported nfs directory on a host",
		// ArgsUsage: "SHARE_REF HOST_REF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Nas_name> and/or <Host_name>."))
			}

			shareName := args[0]
			hostName := args[1]
			path, err := c.Flags().GetString("path")
			if err != nil {
				return cli.FailureResponse(err)
			}

			ac, err := c.Flags().GetBool("ac")
			if err != nil {
				return cli.FailureResponse(err)
			}

			def := protocol.ShareMountRequest{
				Host:      &protocol.Reference{Name: hostName},
				Share:     &protocol.Reference{Name: shareName},
				Path:      path,
				Type:      "nfs",
				WithCache: ac,
			}
			err = ClientSession.Share.Mount(&def, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(cmdline.DecorateTimeoutError(err, "mount of nas", true).Error()))
			}
			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.String("path", abstract.DefaultShareMountPath, "Path to be mounted")
	flags.Bool("ac", false, "Disable cache coherence to improve performances")

	return out
}

func shareUnmountCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "umount",
		Aliases: []string{"unmount"},
		Short:   "Unmount a Share from a host",
		// ArgsUsage: "SHARE_REF HOST_REF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory arguments SHARE_REF and/or HOST_REF."))
			}

			shareName := args[0]
			hostName := args[1]
			def := protocol.ShareMountRequest{
				Host:  &protocol.Reference{Name: hostName},
				Share: &protocol.Reference{Name: shareName},
			}
			err := ClientSession.Share.Unmount(&def, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(cmdline.DecorateTimeoutError(err, "unmount of share", true).Error()))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}

func shareInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "inspect the Share information and clients connected to it",
		// ArgsUsage: "SHARE_REF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", shareCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument SHARE_REF."))
			}

			list, err := ClientSession.Share.Inspect(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(cmdline.DecorateTimeoutError(err, "inspection of share", false).Error()))
			}
			return cli.SuccessResponse(list)
		},
	}
	return out
}
