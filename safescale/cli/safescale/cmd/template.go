/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package cmd

import (
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/safescale/client"
	"github.com/CS-SI/SafeScale/utils"
	clitools "github.com/CS-SI/SafeScale/utils"
)

// TemplateCmd command
var TemplateCmd = cli.Command{
	Name:  "template",
	Usage: "template COMMAND",
	Subcommands: []cli.Command{
		templateList,
	},
}

var templateList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available templates",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "List all available templates in tenant (without any filter)",
		}},
	Action: func(c *cli.Context) error {
		response := utils.NewCliResponse()

		templates, err := client.New().Template.List(c.Bool("all"), client.DefaultExecutionTimeout)
		if err != nil {
			response.Failed(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "list of templates", false).Error())))
		} else {
			response.Succed(templates.GetTemplates())
		}

		return response.GetError()
	},
}
