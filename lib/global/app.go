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

package global

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type app struct {
	*cli.App

	profileCloseFunc func()
}

const (
	BackendCmdLabel = "backend"
	WebUICmdLabel   = "web"
)

var (
	AppCtrl     app
	handlerOnce sync.Once
)

func InitApp() (ferr error) {
	ferr = nil
	handlerOnce.Do(func() {
		rootCmd := &cobra.Command{
			Use:              "safescale",
			Short:            "safescale COMMAND",
			Version:          VersionString(),
			TraverseChildren: true,
		}

		// app.Authors = []cli.Author{
		// 	{
		// 		Name:  "CSGroup",
		// 		Email: "safescale@csgroup.eu",
		// 	},
		// }

		// app.EnableBashCompletion = true

		// app.VersionFlag = &cli.BoolFlag{
		// 	Name:  "version, V",
		// 	Usage: "Print program version",
		// }

		rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
			xerr := LoadSettings(cmd, args)
			if xerr != nil {
				return fmt.Errorf(xerr.Error())
			}

			// Sets profiling
			flag := cmd.Flags().Lookup("profile")
			if flag != nil {
				AppCtrl.profileCloseFunc = debug.Profile(flag.Value.String())
			}

			// Default level is INFO
			logrus.SetLevel(logrus.InfoLevel)

			// Defines trace level wanted by user
			if Config.Verbose || Config.Debug {
				logrus.SetLevel(logrus.DebugLevel)
			}

			if Config.Verbose && Config.Debug {
				logrus.SetLevel(logrus.TraceLevel)
			}

			if strings.Contains(path.Base(os.Args[0]), "-cover") {
				logrus.SetLevel(logrus.TraceLevel)
				Config.Verbose = true
				Config.Debug = true
			}

			return nil
		}

		addFlags(rootCmd)

		AppCtrl.App, ferr = cli.NewApp(rootCmd)
		if ferr != nil {
			AppCtrl.App = nil
			return
		}
	})

	return ferr
}

func AddCommand(cmd *cobra.Command) {
	AppCtrl.App.AddCommand(cmd)
}

// RunApp starts the AppCtrl of the app
func RunApp(ctx context.Context, cleanup func(*cobra.Command)) error {
	if AppCtrl.App == nil {
		return fail.InvalidInstanceContentError("AppCtrl.AppCtrl", "cannot be nil")
	}

	return AppCtrl.App.Run(ctx, cleanup)
}

// VersionString returns the string corresponding to the release of the binary
func VersionString() string {
	version := Version + ", build " + Revision + " (" + BuildDate + ")"
	//goland:noinspection GoBoolExpressions
	if len(Tags) > 1 { // nolint
		version += fmt.Sprintf(", with Tags: (%s)", Tags)
	}
	return version
}

// addFlags adds flags useable in every command
func addFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	if cmd.Name() == BackendCmdLabel || cmd.Name() == WebUICmdLabel {
		flags.String("profile", "", `Profiles binary
            value is a comma-separated list of <keyword> (ie '<keyword>[:<params>][,<keyword>[:<params>]...]) where <keyword>
            can be 'cpu', 'ram', 'trace', and 'web'.
            <params> may contain :
                for 'ram', 'cpu' and 'trace': optional destination folder of output file (default: current working directory)
                for 'web': [<listen addr>][:<listen port>] (default: 'localhost:6060')`,
		)
	}

	flags.BoolP("debug", "d", false, "")
	flags.BoolP("verbose", "v", false, "Increase verbosity")
}
