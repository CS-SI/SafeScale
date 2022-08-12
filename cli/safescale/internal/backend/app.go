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

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	appwide "github.com/CS-SI/SafeScale/v22/lib/utils/appwide"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/oscarpicas/covertool/pkg/exit"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var cleanupOnce sync.Once

// SetCommands initializes
func SetCommands(rootCmd *cobra.Command) *cobra.Command {
	out := &cobra.Command{
		Use:     common.BackendCmdLabel,
		Aliases: []string{"daemon"},
		Short:   "Start SafeScale backend",
	}

	out.AddCommand(
		runCommand(),
		stopCommand(),
	)

	addPersistentPreRunE(out)

	if rootCmd != nil {
		rootCmd.AddCommand(out)
		return rootCmd
	}

	return out
}

func Cleanup() {
	cleanupOnce.Do(func() {
		fmt.Println("Cleaning up...")

		exit.Exit(1)
	})
}

// AddPreRunE completes command PreRun with the necessary for backend
func addPersistentPreRunE(cmd *cobra.Command) error {
	previousCB := cmd.PersistentPreRunE
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) (err error) {
		if previousCB != nil {
			err := previousCB(cmd, args)
			if err != nil {
				return err
			}
		}

		if appwide.Config.ReadConfigFile != "" && appwide.Config.Folders.EtcDir != "" {
			if filepath.Dir(appwide.Config.ReadConfigFile) != appwide.Config.Folders.EtcDir {
				logrus.Infof("For consistency, you should move '%s' file in folder '%s'", appwide.Config.ReadConfigFile+"."+appwide.Config.ReadConfigFileExt, appwide.Config.Folders.EtcDir)
			}
		} else {
			_, err := os.Stat(appwide.Config.Folders.EtcDir + "/settings.yml")
			if err != nil {
				// create settings files from current Config

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
	return nil
}
