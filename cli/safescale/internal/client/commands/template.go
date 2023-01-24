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

	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

var templateCmdName = "template"

// TemplateCommands defines the allowed commands and flags of 'safescale template'
func TemplateCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   "template",
		Short: "template COMMAND",
	}
	out.AddCommand(
		templateListCommand(),
		templateMatchCommand(),
		templateInspectCommand(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

func templateListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available templates",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", templateCmdName, c.Name(), strings.Join(args, ", "))

			all, xerr := c.Flags().GetBool("all")
			if xerr != nil {
				return xerr
			}

			scannedOnly, xerr := c.Flags().GetBool("scanned-only")
			if xerr != nil {
				return xerr
			}

			templates, err := ClientSession.Template.List(all, scannedOnly, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of templates", false).Error())))
			}

			return cli.SuccessResponse(templates.GetTemplates())
		},
	}

	flags := out.Flags()
	flags.Bool("all", false, "Lists all available templates (ignoring any filter set in tenant file)")
	flags.BoolP("scanned-only", "S", false, "Display only templates with scanned information")

	return out
}

func templateMatchCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   "match",
		Short: "List templates that match the SIZING",
		// ArgsUsage: "SIZING",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", templateCmdName, c.Name(), strings.Join(args, ", "))

			sizingAsString := strings.Join(args, ",")
			templates, err := ClientSession.Template.Match(sizingAsString, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of templates", false).Error())))
			}

			return cli.SuccessResponse(templates.GetTemplates())
		},
	}
	return out
}

func templateInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Display available template information",
		// ArgsUsage: "NAME",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", templateCmdName, c.Name(), strings.Join(args, ", "))

			template, err := ClientSession.Template.Inspect(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of template information", false).Error())))
			}

			return cli.SuccessResponse(template)
		},
	}
	return out
}
