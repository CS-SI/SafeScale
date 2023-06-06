/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package azuretf

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// stack ...
type stack struct {
	Config             *stacks.ConfigurationOptions
	AuthOptions        *stacks.AuthenticationOptions
	AzureConfiguration *stacks.AzureConfiguration

	workPath string
	execPath string

	*temporal.MutableTimings
}

func (s *stack) GetType() (string, fail.Error) {
	return "terraform", nil
}

// NullStack is not exposed through API, is needed essentially by tests
func NullStack() api.Stack { // nolint
	return nil
}

func (s *stack) IsNull() bool {
	return s == nil
}

// GetStackName returns the name of the stack
func (s stack) GetStackName() (string, fail.Error) {
	return "azuretf", nil
}

// GetRawConfigurationOptions ...
func (s stack) GetRawConfigurationOptions(context.Context) (stacks.ConfigurationOptions, fail.Error) {
	if valid.IsNil(s) || s.Config == nil {
		return stacks.ConfigurationOptions{}, fail.InvalidInstanceError()
	}
	return *s.Config, nil
}

// GetRawAuthenticationOptions ...
func (s stack) GetRawAuthenticationOptions(context.Context) (stacks.AuthenticationOptions, fail.Error) {
	if valid.IsNil(s) || s.AuthOptions == nil {
		return stacks.AuthenticationOptions{}, fail.InvalidInstanceError()
	}
	return *s.AuthOptions, nil
}

// checkTerraformRequirements will check if terraform is installed and if not, will install it
// returns the path to the terraform executable and an error if any
func checkTerraformRequirements(inctx context.Context, cfg stacks.ConfigurationOptions) (string, error) {
	defaultTerraformPath := utils.AbsPathify("$HOME/.safescale/terraform")

	// try to create defaultTerraformPath
	_ = os.MkdirAll(defaultTerraformPath, 0777)

	// if defaultTerraformPath does not exist, fail
	_, err := os.Stat(defaultTerraformPath)
	if err != nil {
		return "", fmt.Errorf("error checking Terraform directory: %w", err)
	}

	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}

	_, err = os.Stat(filepath.Join(defaultTerraformPath, "terraform"+suffix))
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("error checking Terraform: %w", err)
		}
	} else {
		// check terraform binary version
		// make sure the executable can be run by any user
		err := os.Chmod(filepath.Join(defaultTerraformPath, "terraform"+suffix), 0755)
		if err != nil {
			return "", err
		}
		return filepath.Join(defaultTerraformPath, "terraform"+suffix), nil
	}

	tfVersion := "1.4.2" // the default version
	if cfg.TerraformCfg.TerraformVersion != "" {
		tfVersion = cfg.TerraformCfg.TerraformVersion
	}

	installer := &releases.ExactVersion{
		Product:    product.Terraform,
		InstallDir: defaultTerraformPath,
		Version:    version.Must(version.NewVersion(tfVersion)),
	}

	execPath, err := installer.Install(inctx)
	if err != nil {
		return "", fmt.Errorf("error installing Terraform: %w", err)
	}

	err = os.Chmod(filepath.Join(defaultTerraformPath, "terraform"+suffix), 0755)
	if err != nil {
		return "", err
	}

	return execPath, nil
}

// New Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.AzureConfiguration, cfg stacks.ConfigurationOptions) (*stack, fail.Error) { // nolint
	azStack := &stack{
		Config:             &cfg,
		AuthOptions:        &auth,
		AzureConfiguration: &localCfg,
	}

	if cfg.Timings != nil {
		azStack.MutableTimings = cfg.Timings
		err := azStack.MutableTimings.Update(temporal.NewTimings())
		if err != nil {
			return &stack{}, fail.ConvertError(err)
		}
	} else {
		azStack.MutableTimings = temporal.NewTimings()
	}

	thePath, err := checkTerraformRequirements(context.Background(), cfg)
	if err != nil {
		return nil, fail.Wrap(err, "error installing terraform")
	}

	azStack.execPath = thePath
	defaultWorkPath := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/terraform/%s", azStack.Config.MetadataBucket))

	// try to create defaultWorkPath
	_ = os.MkdirAll(defaultWorkPath, 0777)

	// if defaultWorkPath does not exist, fail
	_, err = os.Stat(defaultWorkPath)
	if err != nil {
		return nil, fail.Wrap(err, "error creating working dir")
	}
	azStack.workPath = defaultWorkPath

	// update the cfg
	cfg.TerraformCfg.ExecutablePath = thePath
	cfg.TerraformCfg.WorkPath = defaultWorkPath

	_, err = git.PlainInit(defaultWorkPath, false)
	if err != nil {
		if err != git.ErrRepositoryAlreadyExists {
			logrus.WithContext(context.Background()).Warnf("failed to initialize git repository in %s: %v", defaultWorkPath, err)
		}
		return azStack, nil
	}

	// create a .gitignore file and commit it
	err = ioutil.WriteFile(filepath.Join(defaultWorkPath, ".gitignore"), []byte("tfstate.backup\n.terraform.lock.hcl\n        .terraform/\n.ssh/\n"), 0644)
	if err != nil {
		return nil, fail.Wrap(err, "error creating .gitignore file")
	}

	r, err := git.PlainOpen(defaultWorkPath)
	if err != nil {
		return nil, fail.Wrap(err, "error opening git repository")
	}

	w, err := r.Worktree()
	if err != nil {
		return nil, fail.Wrap(err, "error getting git worktree")
	}

	_, err = w.Add(".gitignore")
	if err != nil {
		return nil, fail.Wrap(err, "error adding .gitignore to git repository")
	}

	// Commit as safescale operator
	_, err = w.Commit("Added .gitignore", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "safescale operator",
			Email: "safescale@safescale.org",
			When:  time.Now(),
		},
	})
	if err != nil {
		return nil, fail.Wrap(err, "error committing .gitignore to git repository")
	}

	return azStack, nil
}

// Timings returns the instance containing current timing (timeouts, delays) settings
func (s *stack) Timings() (temporal.Timings, fail.Error) {
	if s == nil {
		return temporal.NewTimings(), fail.InvalidInstanceError()
	}
	if s.MutableTimings == nil {
		s.MutableTimings = temporal.NewTimings()
	}
	return s.MutableTimings, nil
}

func (s *stack) UpdateTags(ctx context.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error {
	return fail.NotImplementedError("implement me")
}

func (s *stack) ListTags(ctx context.Context, kind abstract.Enum, id string) (map[string]string, fail.Error) {
	panic("implement me")
}

func (s *stack) DeleteTags(ctx context.Context, kind abstract.Enum, id string, keys []string) fail.Error {
	return fail.NotImplementedError("implement me")
}
