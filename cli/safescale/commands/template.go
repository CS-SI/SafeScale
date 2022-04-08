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
	"github.com/urfave/cli/v2"

	"github.com/CS-SI/SafeScale/v21/lib/client"
	clitools "github.com/CS-SI/SafeScale/v21/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/strprocess"
)

var templateCmdName = "template"

// TemplateCommand command
var TemplateCommand = &cli.Command{
	Name:  "template",
	Usage: "template COMMAND",
	Subcommands: []*cli.Command{
		templateList,
		templateMatch,
		templateInspect,
	},
}

var templateList = &cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available templates",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "all",
			Usage: "Lists all available templates (ignoring any filter set in tenant file)",
		},
		&cli.BoolFlag{
			Name:    "scanned-only",
			Aliases: []string{"S"},
			Usage:   "Display only templates with scanned information",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", templateCmdName, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		templates, err := clientSession.Template.List(c.Bool("all"), c.Bool("scanned-only"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of templates", false).Error())))
		}
		return clitools.SuccessResponse(templates.GetTemplates())
	},
}

var templateMatch = &cli.Command{
	Name:      "match",
	Usage:     "List templates that match the SIZING",
	ArgsUsage: "SIZING",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", templateCmdName, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}
		var sizing []string
		sizing = append(sizing, c.Args().First())
		sizing = append(sizing, c.Args().Tail()...)
		sizingAsString := strings.Join(sizing, ",")
		templates, err := clientSession.Template.Match(sizingAsString, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of templates", false).Error())))
		}
		return clitools.SuccessResponse(templates.GetTemplates())
	},
}

var templateInspect = &cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Display available template information",
	ArgsUsage: "NAME",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", templateCmdName, c.Command.Name, c.Args())

		clientSession, xerr := client.New(c.String("server"))
		if xerr != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
		}

		template, err := clientSession.Template.Inspect(c.Args().First(), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of template information", false).Error())))
		}
		return clitools.SuccessResponse(template)
	},
}
