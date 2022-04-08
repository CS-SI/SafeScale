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
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/v21/lib/client"
	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	clitools "github.com/CS-SI/SafeScale/v21/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/strprocess"
)

var shareCmdName = "share"

// ShareCommand ssh command
var ShareCommand = &cli.Command{
	Name:    "share",
	Aliases: []string{"nas"},
	Usage:   "share COMMAND",
	Subcommands: []*cli.Command{
		shareCreate,
		shareDelete,
		shareMount,
		shareUnmount,
		shareList,
		shareInspect,
	},
}

var shareCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a nfs server on a host and exports a directory",
	ArgsUsage: "<Share_name> <Host_name|Host_ID>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "path",
			Value: abstract.DefaultShareExportedPath,
			Usage: "Path to be exported",
		},
		&cli.BoolFlag{
			Name:  "readonly",
			Usage: "Disallow write requests on this NFS volume",
		},
		&cli.BoolFlag{
			Name:  "rootsquash",
			Usage: "Map requests from uid/gid 0 to the anonymous uid/gid",
		},
		&cli.BoolFlag{
			Name:  "secure",
			Usage: "Requires that requests originate on an Internet port less than IPPORT_RESERVED (1024).",
		},
		&cli.BoolFlag{
			Name:  "async",
			Usage: "This option allows the NFS server to violate the NFS protocol and reply to requests before any changes made by that request have been committed to stable storage",
		},
		&cli.BoolFlag{
			Name:  "nohide",
			Usage: "Enable exports of volumes mounted in the share export path",
		},
		&cli.BoolFlag{
			Name:  "crossmount",
			Usage: "Similar to nohide but it makes it possible for clients to move from the filesystem marked with crossmnt to exported filesystems mounted on it",
		},
		&cli.BoolFlag{
			Name:  "subtreecheck",
			Usage: "Enable subtree checking",
		},
		&cli.StringSliceFlag{
			Name:  "securityModes",
			Usage: "{sys(the default, no security), krb5(authentication only), krb5i(integrity protection), and krb5p(privacy protection)}",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Nas_name> and/or <Host_name>."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		shareName := c.Args().Get(0)
		def := protocol.ShareDefinition{
			Name: shareName,
			Host: &protocol.Reference{Name: c.Args().Get(1)},
			Path: c.String("path"),
			Options: &protocol.NFSExportOptions{
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

		err := clientSession.Share.Create(&def, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(client.DecorateTimeoutError(err, "creation of share", true).Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

var shareDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Remove a share",
	ArgsUsage: "<Share_name> [<Share_name>...]",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Share_name>."))
		}

		var (
			shareList  []string
			errMessage atomic.Value
		)
		errMessage.Store("")

		shareList = append(shareList, c.Args().First())
		shareList = append(shareList, c.Args().Tail()...)

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		if err := clientSession.Share.Delete(shareList, 0); err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of share", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var shareList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List all created shared",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		list, err := clientSession.Share.List(0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(client.DecorateTimeoutError(err, "list of shares", false).Error()))
		}
		return clitools.SuccessResponse(list.ShareList)
	},
}

var shareMount = &cli.Command{
	Name:      "mount",
	Usage:     "Mount an exported nfs directory on a host",
	ArgsUsage: "SHARE_REF HOST_REF",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "path",
			Value: abstract.DefaultShareMountPath,
			Usage: "Path to be mounted",
		},
		&cli.BoolFlag{
			Name:  "ac",
			Usage: "Disable cache coherence to improve performances",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", shareCmdName, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Nas_name> and/or <Host_name>."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		shareName := c.Args().Get(0)
		hostName := c.Args().Get(1)
		path := c.String("path")
		def := protocol.ShareMountDefinition{
			Host:      &protocol.Reference{Name: hostName},
			Share:     &protocol.Reference{Name: shareName},
			Path:      path,
			Type:      "nfs",
			WithCache: c.Bool("ac"),
		}
		err := clientSession.Share.Mount(&def, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(client.DecorateTimeoutError(err, "mount of nas", true).Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

var shareUnmount = &cli.Command{
	Name:      "umount",
	Aliases:   []string{"unmount"},
	Usage:     "Unmount a Share from a host",
	ArgsUsage: "SHARE_REF HOST_REF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args %s", shareCmdName, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory arguments SHARE_REF and/or HOST_REF."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		shareName := c.Args().Get(0)
		hostName := c.Args().Get(1)
		def := protocol.ShareMountDefinition{
			Host:  &protocol.Reference{Name: hostName},
			Share: &protocol.Reference{Name: shareName},
		}
		err := clientSession.Share.Unmount(&def, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(client.DecorateTimeoutError(err, "unmount of share", true).Error()))
		}
		return clitools.SuccessResponse(nil)
	},
}

var shareInspect = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "inspect the Share information and clients connected to it",
	ArgsUsage: "SHARE_REF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", shareCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument SHARE_REF."))
		}

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		list, err := clientSession.Share.Inspect(c.Args().Get(0), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(client.DecorateTimeoutError(err, "inspection of share", false).Error()))
		}
		return clitools.SuccessResponse(list)
	},
}
