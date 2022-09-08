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

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/backend"
	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/client"
	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/webui"
	// Autoload embedded provider drivers
	_ "github.com/CS-SI/SafeScale/v22/lib/backend"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// app.Flags = append(app.Flags, []cli.Flag{
	// 	&cli.StringFlag{
	// 		Name:  "server, S",
	// 		Usage: "Connect to daemon on server SERVER (default: localhost:50051)",
	// 		Value: "",
	// 	},
	// 	&cli.StringFlag{
	// 		Name:  "tenant, T",
	// 		Usage: "Use tenant TENANT (default: none)",
	// 	},
	// }...)

	// Finally, try the remaining possibilities
	err := global.InitApp()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// 1st try to see if command is daemon
	backend.SetCommands()
	webui.SetCommands()
	client.SetCommands()

	// if last argument has "--" or "-" and is NOT help we are probably writing a wrong command
	/*
		{
			if len(os.Args) > 1 {
				last := os.Args[len(os.Args)-1]
				if !(last == "-help" || last == "--help" || last == "-h" || last == "--h") {
					if strings.HasPrefix(last, "-") {
						fmt.Printf("this might be a mistake, flags MUST be used BEFORE arguments: 'safescale subcommand arg1 arg2 --flag1 this_value_is_ignored', you should write 'safescale subcommand --flag1 this_value_now_works arg1 arg2'\n")
					}
				}
			}
		}
	*/

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = global.RunApp(ctx, cleanup)
	if err != nil {
		logrus.Error("Error running cli: " + err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func cleanup(cmd *cobra.Command) {
	// identify the first argument of the command
	precursor, xerr := cli.ElderOfCommand(cmd)
	if xerr != nil {
		logrus.Errorf(xerr.Error())
	}

	// cleans up accordingly with the first argument
	switch precursor.Name() {
	case global.BackendCmdLabel:
		backend.Cleanup()
	case global.WebUICmdLabel:
		webui.Cleanup()
	default:
		client.Cleanup()
	}
}
