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
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

const bucketCmdLabel = "bucket"

func BucketCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   "bucket",
		Short: "bucket COMMAND",
	}
	out.AddCommand(
		bucketListCommand(),
		bucketCreateCommand(),
		bucketDeleteCommand(),
		bucketInspectCommand(),
		bucketMountCommand(),
		bucketUnmountCommand(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

func bucketListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List buckets",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Name(), strings.Join(args, ", "))

			all, err := c.Flags().GetBool("all")
			if err != nil {
				return err
			}

			resp, err := ClientSession.Bucket.List(all, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of buckets", false).Error())))
			}
			return cli.SuccessResponse(resp)
		},
	}
	out.Flags().Bool("all", false, "List all Buckets on tenant (not only those created by SafeScale)")
	return out
}

func bucketCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "Creates a bucket",
		// ArgsUsage: "BUCKET_NAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME."))
			}

			err := ClientSession.Bucket.Create(args[0], temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "creation of bucket", true).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}

func bucketDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"remove", "rm"},
		Short:   "Remove a bucket",
		// ArgsUsage: "BUCKET_NAME [BUCKET_NAME...]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) < 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME."))
			}

			var bucketList []string
			bucketList = append(bucketList, args[0])
			bucketList = append(bucketList, args[1:]...)

			err := ClientSession.Bucket.Delete(bucketList, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of bucket", true).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}

func bucketInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show", "detail"},
		Short:   "Inspect a bucket",
		// ArgsUsage: "BUCKET_NAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME."))
			}

			resp, err := ClientSession.Bucket.Inspect(args[0], temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "inspection of bucket", false).Error())))
			}
			return cli.SuccessResponse(resp)
		},
	}
	return out
}

func bucketMountCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "mount",
		Short: "Mount a bucket on the filesystem of a host",
		// ArgsUsage: "BUCKET_NAME HOST_REF",

		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Name(), strings.Join(args, ", "))
			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME and HOST_REF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument HOST_REF."))
			default:
			}

			path, err := c.Flags().GetString("path")
			if err != nil {
				return err
			}

			err = ClientSession.Bucket.Mount(args[0], args[1], path, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "mount of bucket", true).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	out.Flags().String("path", abstract.DefaultBucketMountPoint, "Mount point of the bucket")
	return out
}

func bucketUnmountCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "umount",
		Aliases: []string{"unmount"},
		Short:   "Unmount a Bucket from the filesystem of a host",
		// ArgsUsage: "BUCKET_NAME HOST_REF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Name(), strings.Join(args, ", "))
			switch len(args) {
			case 0:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME and HOST_REF."))
			case 1:
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument HOST_REF."))
			default:
			}

			err := ClientSession.Bucket.Unmount(args[0], args[1], temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "unmount of bucket", true).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}
	return out
}
