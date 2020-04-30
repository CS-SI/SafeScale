/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var bucketCmdName = "bucket"

// BucketCmd bucket command
var BucketCmd = &cli.Command{
	Name:  "bucket",
	Usage: "bucket COMMAND",
	Subcommands: []*cli.Command{
		bucketList,
		bucketCreate,
		bucketDelete,
		bucketInspect,
		bucketMount,
		bucketUnmount,
	},
}

var bucketList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "ErrorList buckets",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", bucketCmdName, c.Command.Name, c.Args())
		resp, err := client.New().Bucket.List(0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of buckets", false).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var bucketCreate = &cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Creates a bucket",
	ArgsUsage: "<Bucket_name>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", bucketCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Bucket_name>."))
		}

		err := client.New().Bucket.Create(c.Args().Get(0), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of bucket", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var bucketDelete = &cli.Command{
	Name:      "delete",
	Aliases:   []string{"remove", "rm"},
	Usage:     "Delete a bucket",
	ArgsUsage: "<Bucket_name> [<Bucket_name>...]",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", bucketCmdName, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Bucket_name>."))
		}

		var bucketList []string
		bucketList = append(bucketList, c.Args().First())
		bucketList = append(bucketList, c.Args().Tail()...)

		err := client.New().Bucket.Delete(bucketList, temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of bucket", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var bucketInspect = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show", "detail"},
	Usage:     "Inspect a bucket",
	ArgsUsage: "<Bucket_name>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", bucketCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Bucket_name>."))
		}

		resp, err := client.New().Bucket.Inspect(c.Args().Get(0), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of bucket", false).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var bucketMount = &cli.Command{
	Name:      "mount",
	Usage:     "Mount a bucket on the filesystem of an host",
	ArgsUsage: "<Bucket_name> <Host_name>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "path",
			Value: abstract.DefaultBucketMountPoint,
			Usage: "Mount point of the bucket",
		},
	},
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", bucketCmdName, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Bucket_name> and/or <Host_name>."))
		}

		err := client.New().Bucket.Mount(c.Args().Get(0), c.Args().Get(1), c.String("path"), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "mount of bucket", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var bucketUnmount = &cli.Command{
	Name:      "umount",
	Aliases:   []string{"unmount"},
	Usage:     "Unmount a bucket from the filesystem of an host",
	ArgsUsage: "<Bucket_name> <Host_name>",
	Action: func(c *cli.Context) error {
		logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", bucketCmdName, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Bucket_name> and/or <Host_name>."))
		}

		err := client.New().Bucket.Unmount(c.Args().Get(0), c.Args().Get(1), temporal.GetExecutionTimeout())
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unmount of bucket", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
