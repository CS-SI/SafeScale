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

	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var imageCmdName = "image"

// ImageCommands command
func ImageCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   "image",
		Short: "image COMMAND",
	}
	out.AddCommand(imageListCommand())
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

func imageListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available images",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", imageCmdName, c.Name(), strings.Join(args, ", "))

			all, err := c.Flags().GetBool("all")
			if err != nil {
				return err
			}

			images, err := ClientSession.Image.List(all, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of images", false).Error())))
			}
			return cli.SuccessResponse(images.GetImages())
		},
	}
	out.Flags().BoolP("all", "a", false, "List all available images in tenant (without any filter)")
	return out
}
