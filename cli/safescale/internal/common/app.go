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

package common

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/utils/appwide"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var ValidConfigFilenameExts = []string{"json", "js", "yaml", "yml", "toml", "tml"}

func NewApp() (*cobra.Command, error) {
	app := &cobra.Command{
		Use:              "safescale",
		Short:            "safescale COMMAND",
		Version:          Version + ", build " + Revision + " compiled with " + runtime.Version() + " (" + BuildDate + ")",
		TraverseChildren: true,
	}
	if len(Tags) > 0 { // nolint
		app.Version += fmt.Sprintf(", with Build Tags: (%s)", Tags)
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

	app.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		xerr := appwide.LoadSettings(cmd, args)
		if xerr != nil {
			return fmt.Errorf(xerr.Error())
		}

		// Sets profiling
		flag := cmd.Flags().Lookup("profile")
		if flag != nil {
			ProfileCloseFunc = debug.Profile(flag.Value.String())
		}

		// Default level is INFO
		logrus.SetLevel(logrus.InfoLevel)

		// Defines trace level wanted by user
		if appwide.Config.Verbose || appwide.Config.Debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if appwide.Config.Verbose && appwide.Config.Debug {
			logrus.SetLevel(logrus.TraceLevel)
		}

		if strings.Contains(path.Base(os.Args[0]), "-cover") {
			logrus.SetLevel(logrus.TraceLevel)
			appwide.Config.Verbose = true
			appwide.Config.Debug = true
		}

		return nil
	}

	return app, nil
}

func RunApp(ctx context.Context, app *cobra.Command, cleanup func(*cobra.Command)) error {
	if app == nil {
		return fail.InvalidParameterCannotBeNilError("app")
	}

	signalCh := make(chan os.Signal, 1)
	// Starts ctrl+c handler before app.RunContext()
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		var crash error
		defer fail.SilentOnPanic(&crash)

		for {
			sig := <-signalCh
			_ = sig

			if cleanup != nil {
				cleanup(app)
			}

			if ProfileCloseFunc != nil {
				ProfileCloseFunc()
				ProfileCloseFunc = nil
			}
		}
	}()

	err := app.ExecuteContext(ctx)
	if err != nil {
		fmt.Println("Error Running safescale: " + err.Error())
	}

	return nil
}

func VersionString() string {
	version := Version + ", build " + Revision + " (" + BuildDate + ")"
	//goland:noinspection GoBoolExpressions
	if len(Tags) > 1 { // nolint
		version += fmt.Sprintf(", with Tags: (%s)", Tags)
	}
	return version
}

// AddFlags adds flags useable in every command
func AddFlags(cmd *cobra.Command) {
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
