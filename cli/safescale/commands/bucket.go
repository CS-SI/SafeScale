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
	"os"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/client"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

const bucketCmdLabel = "bucket"

// BucketCommand bucket command
var BucketCommand = cli.Command{
	Name:  "bucket",
	Usage: "bucket COMMAND",
	Subcommands: cli.Commands{
		bucketList,
		bucketCreate,
		bucketDelete,
		bucketInspect,
		bucketMount,
		bucketUnmount,
		bucketDownload,
		bucketUpload,
		bucketClear,
	},
}

var bucketList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List buckets",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "List all Buckets on tenant (not only those created by SafeScale)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Command.Name, c.Args())

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Listing buckets"
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

		resp, err := ClientSession.Bucket.List(c.Bool("all"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of buckets", false).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var bucketDownload = cli.Command{
	Name:    "download",
	Aliases: []string{"download"},
	Usage:   "Downloads a bucket",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "output",
			Value:    "",
			Required: true,
			Usage:    "filename where the zipped bucket is stored",
		},
	},
	ArgsUsage: "BUCKET_NAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME."))
		}

		filename := c.String("output")
		if !strings.HasSuffix(strings.ToLower(filename), ".zip") {
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("output file should have .zip suffix"))
		}

		clientSession, xerr := client.New(c.String("server"), c.String("tenant"))
		if xerr != nil {
			return clitools.FailureResponse(xerr)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Downloading bucket"
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

		dr, err := clientSession.Bucket.Download(c.Args().Get(0), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bucket download", true).Error())))
		}

		err = os.WriteFile(filename, dr.Content, 0644)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		return clitools.SuccessResponse(nil)
	},
}

var bucketClear = cli.Command{
	Name:      "clear",
	Aliases:   []string{"clear"},
	Usage:     "Clears a bucket",
	Flags:     []cli.Flag{},
	ArgsUsage: "BUCKET_NAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME."))
		}

		clientSession, xerr := client.New(c.String("server"), c.String("tenant"))
		if xerr != nil {
			return clitools.FailureResponse(xerr)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Cleaning bucket"
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

		err := clientSession.Bucket.Clear(c.Args().Get(0), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bucket download", true).Error())))
		}

		return clitools.SuccessResponse(nil)
	},
}

var bucketUpload = cli.Command{
	Name:      "upload",
	Aliases:   []string{"upload"},
	Usage:     "Uploads a bucket",
	Flags:     []cli.Flag{},
	ArgsUsage: "BUCKET_NAME LOCAL_BUCKET_DIR",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Command.Name, c.Args())
		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME and LOCAL_BUCKET_DIR."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument LOCAL_BUCKET_DIR."))
		default:
		}

		clientSession, xerr := client.New(c.String("server"), c.String("tenant"))
		if xerr != nil {
			return clitools.FailureResponse(xerr)
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Uploading bucket"
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

		err := clientSession.Bucket.Upload(c.Args().Get(0), c.Args().Get(1), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "bucket download", true).Error())))
		}

		return clitools.SuccessResponse(nil)
	},
}

var bucketCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Creates a bucket",
	ArgsUsage: "BUCKET_NAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Creating bucket"
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

		err := ClientSession.Bucket.Create(c.Args().Get(0), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of bucket", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var bucketDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"remove", "rm"},
	Usage:     "Remove a bucket",
	ArgsUsage: "BUCKET_NAME [BUCKET_NAME...]",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME."))
		}

		var bucketList []string
		bucketList = append(bucketList, c.Args().First())
		bucketList = append(bucketList, c.Args().Tail()...)

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Deleting bucket"
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

		err := ClientSession.Bucket.Delete(bucketList, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of bucket", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var bucketInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show", "detail"},
	Usage:     "Inspect a bucket",
	ArgsUsage: "BUCKET_NAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME."))
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Inspecting bucket"
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

		resp, err := ClientSession.Bucket.Inspect(c.Args().Get(0), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of bucket", false).Error())))
		}
		return clitools.SuccessResponse(resp)
	},
}

var bucketMount = cli.Command{
	Name:      "mount",
	Usage:     "Mount a bucket on the filesystem of a host",
	ArgsUsage: "BUCKET_NAME HOST_REF",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: abstract.DefaultBucketMountPoint,
			Usage: "Mount point of the bucket",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Command.Name, c.Args())
		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME and HOST_REF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument HOST_REF."))
		default:
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Mounting bucket"
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

		err := ClientSession.Bucket.Mount(c.Args().Get(0), c.Args().Get(1), c.String("path"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "mount of bucket", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var bucketUnmount = cli.Command{
	Name:      "umount",
	Aliases:   []string{"unmount"},
	Usage:     "Unmount a Bucket from the filesystem of a host",
	ArgsUsage: "BUCKET_NAME HOST_REF",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", bucketCmdLabel, c.Command.Name, c.Args())
		switch c.NArg() {
		case 0:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument BUCKET_NAME and HOST_REF."))
		case 1:
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument HOST_REF."))
		default:
		}

		if beta := os.Getenv("SAFESCALE_BETA"); beta != "" {
			description := "Unmounting bucket"
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

		err := ClientSession.Bucket.Unmount(c.Args().Get(0), c.Args().Get(1), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unmount of bucket", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}
