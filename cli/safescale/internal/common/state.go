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

package common

import (
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"syscall"

	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	filelock "github.com/MichaelS11/go-file-lock"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type State struct {
	Current struct {
		Organization string
		Project      string
		Tenant       string
	}

	homedir      string
	configFolder string
}

func NewState() (State, error) {
	// -- save tenant as default tenant for current user --
	currentUser, err := user.Current()
	if err != nil {
		return State{}, err
	}

	configFolder := filepath.Join(currentUser.HomeDir, ".safescale")
	err = os.Mkdir(configFolder, 0600)
	if err != nil {
		switch cerr := err.(type) {
		case *fs.PathError:
			if cerr.Err != syscall.EEXIST {
				return State{}, fail.Wrap(cerr, "failed to create '%s' directory", configFolder)
			}
			// continue

		default:
			return State{}, fail.Wrap(cerr, "failed to create '%s' directory", configFolder)
		}
	}

	out := State{
		homedir:      currentUser.HomeDir,
		configFolder: configFolder,
	}
	return out, nil
}

// IsNull tells if instance represents a null value
func (s *State) IsNull() bool {
	return s == nil || s.homedir == "" || s.configFolder == ""
}

// Read reads the state config file $HOME/.safescale/state.{json,yaml,toml}
func (s *State) Read() error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}

	// -- save tenant as default tenant for current user --
	viperInstance := viper.New()
	viperInstance.AddConfigPath(s.configFolder)
	viperInstance.SetConfigName("state")
	err := viperInstance.ReadInConfig()
	if err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			// continue
		default:
			return fail.Wrap(err, "failed to read state config file")
		}
	}

	s.Current.Organization = viperInstance.GetString("organization.current")
	s.Current.Project = viperInstance.GetString("organization.project")
	s.Current.Tenant = viperInstance.GetString("organization.tenant")
	return nil
}

// Update writes state changes to state config file
func (s State) Update() error {
	viperInstance := viper.New()
	viperInstance.AddConfigPath(s.configFolder)
	viperInstance.SetConfigName("state")

	var fl *filelock.LockHandle
	err := viperInstance.ReadInConfig()
	if err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			stateFile := filepath.Join(s.configFolder, "state.yaml")
			file, err := os.Create(stateFile)
			if err != nil {
				return fail.Wrap(err, "failed to create state file '%s'")
			}
			file.Close()

			// lock config file to prevent simultaneous update
			fl, err = filelock.New(viperInstance.ConfigFileUsed())
			if err != nil {
				return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, fail.Wrap(err, "failed to lock file '%s'", viperInstance.ConfigFileUsed()).Error()))
			}

			// Prepares viper instance for update to come
			viperInstance.SetConfigFile(stateFile)
			viperInstance.SetConfigType("yaml")
			viperInstance.SetConfigPermissions(0600)

		default:
			return fail.Wrap(err, "failed to read 'state.{yaml,json,toml}' file in '%s'", s.configFolder)
		}
	} else {
		// lock config file to prevent simultaneous update
		fl, err = filelock.New(viperInstance.ConfigFileUsed())
		if err != nil {
			return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, fail.Wrap(err, "failed to lock file '%s'", viperInstance.ConfigFileUsed()).Error()))
		}
	}
	defer func() { _ = fl.Unlock() }()

	viperInstance.Set("organization.current", s.Current.Organization)
	viperInstance.Set("project.current", s.Current.Project)
	viperInstance.Set("tenant.current", s.Current.Tenant)

	err = viperInstance.WriteConfig()
	if err != nil {
		return cli.FailureResponse(cli.ExitOnErrorWithMessage(exitcode.Run, fail.Wrap(err, "failed to update '%s/%s' file", s.configFolder, viperInstance.ConfigFileUsed()).Error()))
	}

	return nil
}
