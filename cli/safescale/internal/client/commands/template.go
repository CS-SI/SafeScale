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

	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var templateCmdName = "template"

// TemplateCommand command
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

			templates, err := ClientSession.Template.List(c.Flags().GetBool("all"), c.Flags().GetBool("scanned-only"), 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of templates", false).Error())))
			}
			return clitools.SuccessResponse(templates.GetTemplates())
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

			var sizing []string
			sizing = append(sizing, args[0])
			sizing = append(sizing, args[1:]...)
			sizingAsString := strings.Join(sizing, ",")
			templates, err := ClientSession.Template.Match(sizingAsString, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of templates", false).Error())))
			}
			return clitools.SuccessResponse(templates.GetTemplates())
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
				return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of template information", false).Error())))
			}
			return clitools.SuccessResponse(template)
		},
	}
	return out
}
