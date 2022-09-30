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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
)

// SetCommands adds commands in global.AppCtrl
func SetCommands() {
	out := &cobra.Command{
		Use:     global.BackendCmdLabel,
		Aliases: []string{"daemon"},
		Short:   "Start SafeScale backend",
	}

	out.AddCommand(
		runCommand(),
		stopCommand(),
	)

	addPreRunE(out)

	global.AddCommand(out)
}

var cleanupOnce sync.Once

// Cleanup ensures correct cleaning of backend on exit
func Cleanup() {
	cleanupOnce.Do(func() {
		fmt.Println("Cleaning up...")
	})
}

// AddPreRunE completes command PreRun with the necessary for backend
func addPreRunE(cmd *cobra.Command) {
	previousCB := cmd.PreRunE
	cmd.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		if previousCB != nil {
			err := previousCB(cmd, args)
			if err != nil {
				return err
			}
		}

		if global.Settings.ReadConfigFile != "" && global.Settings.Folders.EtcDir != "" {
			if filepath.Dir(global.Settings.ReadConfigFile) != global.Settings.Folders.EtcDir {
				logrus.Infof("For consistency, you should move '%s' file in folder '%s'", global.Settings.ReadConfigFile+"."+global.Settings.ReadConfigFileExt, global.Settings.Folders.EtcDir)
			}
		} else {
			_, err := os.Stat(global.Settings.Folders.EtcDir + "/settings.yaml")
			if err != nil {
				// create settings files from current Settings

			}
		}

		// Define trace settings of the application (what to trace if trace is wanted)
		// TODO: is it the good behavior ? Shouldn't we fail ?
		// If trace settings cannot be registered, report it but do not fail
		// TODO: introduce use of configuration file with autoreload on change
		err = tracing.RegisterTraceSettings(traceSettings())
		if err != nil {
			return err
		}

		return nil
	}
}
