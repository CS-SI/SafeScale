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
    "github.com/urfave/cli/v2"

    "github.com/CS-SI/SafeScale/lib/client"
    clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
    "github.com/CS-SI/SafeScale/lib/utils/cli/enums/exitcode"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    "github.com/CS-SI/SafeScale/lib/utils/strprocess"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var templateCmdName = "template"

// TemplateCommand command
var TemplateCommand = &cli.Command{
    Name:  "template",
    Usage: "template COMMAND",
    Subcommands: []*cli.Command{
        templateList,
    },
}

var templateList = &cli.Command{
    Name:    "list",
    Aliases: []string{"ls"},
    Usage:   "ErrorList available templates",
    Flags: []cli.Flag{
        &cli.BoolFlag{
            Name:  "all",
            Usage: "ErrorList all available templates in tenant (without any filter)",
        }},
    Action: func(c *cli.Context) error {
        logrus.Tracef("SafeScale command: {%s}, {%s} with args {%s}", templateCmdName, c.Command.Name, c.Args())

        clientSession, xerr := client.New(c.String("server"))
        if xerr != nil {
            return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, xerr.Error()))
        }

        templates, err := clientSession.Template.List(c.Bool("all"), temporal.GetExecutionTimeout())
        if err != nil {
            err = fail.FromGRPCStatus(err)
            return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of templates", false).Error())))
        }
        return clitools.SuccessResponse(templates.GetTemplates())
    },
}
