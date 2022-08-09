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
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

var templateCmdName = "template"

// TemplateCommand command
var TemplateCommand = &cobra.Command{
	Name:  "template",
	Usage: "template COMMAND",
	Subcommands: cli.Commands{
		templateList,
		templateMatch,
		templateInspect,
	},
}

var templateList = &cobra.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available templates",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "Lists all available templates (ignoring any filter set in tenant file)",
		},
		cli.BoolFlag{
			Name:  "scanned-only, S",
			Usage: "Display only templates with scanned information",
		},
	},
	RunE: func(c *cobra.Command, args []string) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", templateCmdName, c.Command.Name, c.Args())

		defer interactiveFeedback("Listing templates")()

		templates, err := ClientSession.Template.List(c.Bool("all"), c.Bool("scanned-only"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of templates", false).Error())))
		}
		return clitools.SuccessResponse(templates.GetTemplates())
	},
}

var templateMatch = &cobra.Command{
	Name:      "match",
	Usage:     "List templates that match the SIZING",
	ArgsUsage: "SIZING",
	RunE: func(c *cobra.Command, args []string) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", templateCmdName, c.Command.Name, c.Args())

		var sizing []string
		sizing = append(sizing, c.Args().First())
		sizing = append(sizing, c.Args().Tail()...)
		sizingAsString := strings.Join(sizing, ",")

		defer interactiveFeedback("Filtering templates")()

		templates, err := ClientSession.Template.Match(sizingAsString, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of templates", false).Error())))
		}
		return clitools.SuccessResponse(templates.GetTemplates())
	},
}

var templateInspect = &cobra.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Display available template information",
	ArgsUsage: "NAME",
	RunE: func(c *cobra.Command, args []string) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", templateCmdName, c.Command.Name, c.Args())

		defer interactiveFeedback("Inspecting templates")()

		template, err := ClientSession.Template.Inspect(c.Args().First(), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of template information", false).Error())))
		}
		return clitools.SuccessResponse(template)
	},
}
