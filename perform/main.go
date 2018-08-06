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

package main

import (
	"fmt"
	"os"
	"time"

	cli "github.com/jawher/mow.cli"

	"github.com/CS-SI/SafeScale/perform/cmds"

	_ "github.com/CS-SI/SafeScale/providers/cloudwatt"      // Imported to initialise provider cloudwatt
	_ "github.com/CS-SI/SafeScale/providers/flexibleengine" // Imported to initialise provider flexibleengine
	_ "github.com/CS-SI/SafeScale/providers/opentelekom"    // Imported to initialise provider opentelekom
	_ "github.com/CS-SI/SafeScale/providers/ovh"            // Imported to initialise provider ovh
)

const (
	address           = "localhost:50051"
	timeoutCtxDefault = 10 * time.Second
	timeoutCtxHost    = 2 * time.Minute
)

func main() {
	app := cli.App("perform", "SafeScale perform")
	//app.Version = "0.1.0"
	/*app.Authors = []cli.Author{
		cli.Author{
			Name:  "CS-SI",
			Email: "safescale@c-s.fr",
		},
	}
	app.EnableBashCompletion = true*/

	app.Command("create", "create perform cluster", cmds.CreateCmd)
	app.Command("expand", "Add a node to the perform cluster", cmds.ExpandCmd)
	app.Command("shrink", "Remove a node from perform cluster", cmds.ShrinkCmd)
	app.Command("dcos", "execute dcos command", cmds.DcosCmd)
	app.Command("marathon", "Executes marathon command", cmds.MarathonCmd)
	app.Command("kubectl", "Executes kubectl command", cmds.KubectlCmd)
	app.Command("deploy", "Deploy a package or service on cluster", cmds.DeployCmd)

	verbose := app.BoolOpt("verbose v", false, "Increase verbosity")
	debug := app.BoolOpt("debug d", false, "Enable debug mode")
	rebrand := app.StringOpt("rebrand", "", "Prefix to use when calling external commands")

	app.Before = func() {
		if *verbose {
			fmt.Printf("Verbosity wanted.")
		}
		if *debug {
			fmt.Printf("Debug enabled")
		}
		if *rebrand != "" {
			cmds.RebrandingPrefix = *rebrand
		}
	}

	app.Run(os.Args)
}
