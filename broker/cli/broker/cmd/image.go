/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"encoding/json"
	"fmt"

	"github.com/CS-SI/SafeScale/broker/client"
	"github.com/urfave/cli"
)

// ImageCmd command
var ImageCmd = cli.Command{
	Name:  "image",
	Usage: "image COMMAND",
	Subcommands: []cli.Command{
		imageList,
	},
}

var imageList = cli.Command{
	Name:  "list",
	Usage: "List available images",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all",
			Usage: "List all available images in tenant (without any filter)",
		}},
	Action: func(c *cli.Context) error {
		images, err := client.New().Image.List(c.Bool("all"), 0)
		if err != nil {
			return fmt.Errorf("Could not get image list: %v", err)
		}
		out, _ := json.Marshal(images)
		fmt.Println(string(out))
		return nil
	},
}
