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
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	appwide "github.com/CS-SI/SafeScale/v22/lib/utils/app"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func NewApp() (*cli.App, error) {
	app := cli.NewApp()
	app.Writer = os.Stderr
	app.Name = "safescale"
	app.Usage = "safescale COMMAND"
	app.Version = Version + ", build " + Revision + " compiled with " + runtime.Version() + " (" + BuildDate + ")"
	//goland:noinspection GoBoolExpressions
	if len(Tags) > 1 { // nolint
		app.Version += fmt.Sprintf(", with Build Tags: (%s)", Tags)
	}
	app.Authors = []cli.Author{
		{
			Name:  "CSGroup",
			Email: "safescale@csgroup.eu",
		},
	}

	app.EnableBashCompletion = true

	cli.VersionFlag = &cli.BoolFlag{
		Name:  "version, V",
		Usage: "Print program version",
	}

	app.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "verbose, v",
			Usage: "Increase verbosity",
		},
		&cli.BoolFlag{
			Name:  "debug, d",
			Usage: "Show debug information",
		},
		&cli.StringFlag{
			Name: "profile",
			Usage: `Profiles binary
            value is a comma-separated list of <keyword> (ie '<keyword>[:<params>][,<keyword>[:<params>]...]) where <keyword>
            can be 'cpu', 'ram', 'trace', and 'web'.
            <params> may contain :
                for 'ram', 'cpu' and 'trace': optional destination folder of output file (default: current working directory)
                for 'web': [<listen addr>][:<listen port>] (default: 'localhost:6060')`,
		},
	}

	app.Before = func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)

		// Sets profiling
		if c.IsSet("profile") {
			what := c.String("profile")
			ProfileCloseFunc = debug.Profile(what)
		}

		// Default level is INFO
		logrus.SetLevel(logrus.InfoLevel)

		// Defines trace level wanted by user
		if appwide.Verbose = c.Bool("verbose"); appwide.Verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if appwide.Debug = c.Bool("debug"); appwide.Debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if appwide.Debug && appwide.Verbose {
			logrus.SetLevel(logrus.TraceLevel)
		}

		if strings.Contains(path.Base(os.Args[0]), "-cover") {
			logrus.SetLevel(logrus.TraceLevel)
			appwide.Verbose = true
			appwide.Debug = true
		}

		// VPL: moved in commands package
		// commands.ClientSession, err = client.New(c.String("server"), c.String("tenant"))
		// if err != nil {
		// 	return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		// }
		//
		return nil
	}

	return app, nil
}

func RunApp(app *cli.App, signalCh chan os.Signal, cleanup func()) error {
	if app == nil {
		return fail.InvalidParameterCannotBeNilError("app")
	}

	// Adding code to react to external signals app.Before
	previousBefore := app.Before
	app.Before = func(c *cli.Context) (ferr error) {
		if previousBefore != nil {
			err := previousBefore(c)
			if err != nil {
				return err
			}
		}

		go func() {
			var crash error
			defer fail.SilentOnPanic(&crash)

			for {
				<-signalCh

				if ProfileCloseFunc != nil {
					ProfileCloseFunc()
					ProfileCloseFunc = nil
				}

				if cleanup != nil {
					cleanup()
				}
				// cancelfunc()
			}
		}()

		return nil
	}

	// VPL: there is no RunContext in urfave/cli/v1
	// err := app.RunContext(mainCtx, os.Args)
	err := app.Run(os.Args)
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
