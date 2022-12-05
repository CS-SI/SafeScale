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

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type App struct {
	rootCmd *cobra.Command

	profileCloseFunc func()
	cancelFunc       func()

	doneCh chan struct{}
}

// NewApp creates an instance of App struct to control application behaviour
func NewApp(cobraRootCmd *cobra.Command) (*App, error) {
	if cobraRootCmd == nil {
		return nil, fail.InvalidParameterCannotBeNilError("cobraRootCmd")
	}

	out := &App{
		rootCmd: cobraRootCmd,
		doneCh:  make(chan struct{}, 1),
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

	return out, nil
}

// AddCommand adds a command to the App
func (app *App) AddCommand(cmd ...*cobra.Command) error {
	if valid.IsNull(app) {
		return fail.InvalidInstanceError()
	}

	if cmd == nil {
		return nil
	}

	app.rootCmd.AddCommand(cmd...)
	return nil
}

// Run starts the behaviour of the App
func (app *App) Run(ctx context.Context, cleanup func(*cobra.Command)) error {
	if app == nil {
		return fail.InvalidParameterCannotBeNilError("app")
	}

	signalCh := make(chan os.Signal, 1)
	// Starts ctrl+c handler before app.RunContext()
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGKILL, syscall.SIGQUIT, syscall.SIGTERM)

	go func() {
		var crash error
		defer fail.SilentOnPanic(&crash)

		for {
			sig := <-signalCh
			_ = sig

			if cleanup != nil {
				cleanup(app.rootCmd)
			}

			if app.profileCloseFunc != nil {
				app.profileCloseFunc()
				app.profileCloseFunc = nil
			}

			app.Exit(1, fmt.Sprintf("received signal %s", sig))
			return
		}
	}()

	ctx, app.cancelFunc = context.WithCancel(ctx)
	err := app.rootCmd.ExecuteContext(ctx)
	if err != nil {
		app.doneCh <- struct{}{}
		// fmt.Println("Error Running safescale: " + err.Error())
		return err
	}

	app.doneCh <- struct{}{}
	return nil
}

// Exit calls the cancel func to trigger cancellation and wait Run() finishes, then exit with exitCode
func (app *App) Exit(exitCode int, exitMsg string) {
	if valid.IsNull(app) {
		os.Exit(exitCode)
	}

	if app.cancelFunc != nil {
		app.cancelFunc()
	}

	<-app.doneCh

	if exitCode > 0 {
		_, err := fmt.Fprintln(os.Stderr, exitMsg)
		if err != nil {
			fmt.Println(exitMsg+" (failed to output on stderr: %v)", err)
		}
	} else {
		fmt.Println(exitMsg)
	}
	os.Exit(exitCode)
}
