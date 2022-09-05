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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package commands

import (
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	labelCmdName = "label"
	tagCmdName   = "tag"
)

// LabelCommands label command
func LabelCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   labelCmdName,
		Short: labelCmdName + " COMMAND",
	}
	out.AddCommand(
		labelListCommand(),
		labelInspectCommand(),
		labelDeleteCommand(),
		labelCreateCommand(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

func labelListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available Labels",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", labelCmdName, c.Name(), strings.Join(args, ", "))

			list, err := ClientSession.Label.List(false, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of Labels", false).Error())))
			}

			var output []map[string]interface{}
			jsoned, xerr := json.Marshal(list.Labels)
			if xerr == nil {
				xerr = json.Unmarshal(jsoned, &output)
			}
			if xerr != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(xerr.Error())))
			}

			for _, v := range output {
				delete(v, "has_default")
			}
			return cli.SuccessResponse(output)
		},
	}
	return out
}

func labelInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Inspect Label",
		// ArgsUsage: "LABELREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", labelCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument LABELREF."))
			}

			labelInfo, err := ClientSession.Label.Inspect(args[0], false, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "inspection of Label", false).Error())))
			}

			output := map[string]interface{}{
				"id":            labelInfo.Id,
				"name":          labelInfo.Name,
				"default_value": labelInfo.DefaultValue,
				"hosts":         make([]interface{}, 0),
			}
			for _, v := range labelInfo.Hosts {
				item := map[string]string{
					"id":    v.Host.Id,
					"name":  v.Host.Name,
					"value": v.Value,
				}
				output["hosts"] = append(output["hosts"].([]interface{}), item)
			}
			return cli.SuccessResponse(output)
		},
	}
	return out
}

func labelDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"rm", "remove"},
		Short:   "Remove Label",
		// ArgsUsage: "LABELREF [LABELREF...]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", labelCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) < 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument LABELREF."))
			}

			err := ClientSession.Label.Delete(args, false, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of Label", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}

	out.Flags().Bool("force", false, "Force deletion even if the Label has resources bound to it")

	return out
}

func labelCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "Create a Label",
		//ArgsUsage: "LABELNAME [DEFAULTVALUE]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", labelCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Tag_name>. "))
			}

			value, err := c.Flags().GetString("value")
			if err != nil {
				return err
			}
			label, err := ClientSession.Label.Create(args[0], true, value, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "creation of Label", true).Error())))
			}
			return cli.SuccessResponse(label)
		},
	}

	out.Flags().String("value", "", "defines the default value of the Label")

	return out
}

// TagCommand tag command
func TagCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   "tag",
		Short: "tag COMMAND",
	}
	out.AddCommand(
		tagListCommand(),
		tagInspectCommand(),
		tagDeleteCommand(),
		tagCreateCommand(),
	)
	return out
}

func tagListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available Tags in Tenant",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Name(), strings.Join(args, ", "))

			list, err := ClientSession.Label.List(true, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of Tags", false).Error())))
			}

			// Remove hosts from list content for this command
			jsoned, err := json.Marshal(list.Labels)
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of hosts", false).Error())))
			}

			var body []map[string]interface{}
			err = json.Unmarshal(jsoned, &body)
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of hosts", false).Error())))
			}

			for _, v := range body {
				delete(v, "hosts")
			}
			return cli.SuccessResponse(body)
		},
	}
	return out
}

func tagInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Inspect tag",
		// ArgsUsage: "TAGREF",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument TAGREF."))
			}

			tagInfo, err := ClientSession.Label.Inspect(args[0], true, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "inspection of Tag", false).Error())))
			}

			if tagInfo.HasDefault {
				return cli.FailureResponse(cli.ExitOnRPC(fmt.Sprintf("inspection of Tag: '%s' is a Label", args[0])))
			}

			output := map[string]interface{}{
				"id":    tagInfo.Id,
				"name":  tagInfo.Name,
				"hosts": make([]interface{}, 0),
			}
			for _, v := range tagInfo.Hosts {
				item := map[string]string{
					"id":   v.Host.Id,
					"name": v.Host.Name,
				}
				output["hosts"] = append(output["hosts"].([]interface{}), item)
			}
			return cli.SuccessResponse(output)
		},
	}
	return out
}

func tagDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"rm", "remove"},
		Short:   "Remove tag",
		//ArgsUsage: "TAGREF [TAGREF...]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) < 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument TAGREF."))
			}

			var list []string
			list = append(list, args[0])
			list = append(list, args[1:]...)

			err := ClientSession.Label.Delete(list, true, temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of Tag", false).Error())))
			}
			return cli.SuccessResponse(nil)
		},
	}

	out.Flags().Bool("force", false, "Force deletion even if the tag has resources bound")

	return out
}

func tagCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "Create a tag",
		//ArgsUsage: "TAGNAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", tagCmdName, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument TAGNAME."))
			}

			tag, err := ClientSession.Label.Create(args[0], false, "", temporal.ExecutionTimeout())
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "creation of Tag", true).Error())))
			}

			return cli.SuccessResponse(tag)
		},
	}
	return out
}
