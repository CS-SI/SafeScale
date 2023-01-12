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

package internal

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/hashicorp/terraform-exec/tfexec"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type (
	// ProviderUsingTerraform ...
	ProviderUsingTerraform interface {
		iaasapi.Provider

		TerraformDefinitionSnippet() string
		TerraformerOptions() options.Options
		Name() string
		EmbeddedFS() embed.FS // returns the embed.FS containing snippets
	}
)

// renderer is an implementation of Terraformer interface
type renderer struct {
	mu           *sync.Mutex
	executor     *tfexec.Terraform
	provider     ProviderUsingTerraform
	scope        api.ScopeLimitedToTerraformerUse
	opts         options.Options
	config       api.Configuration
	env          map[string]string // contains environment variables to set at each call
	buildPath    string
	lastFilename string
	saveLockFile bool
	dirty        bool
	closed       bool
}

const (
	consulBackendSnippetPath     = "snippets/consul-backend.tf"
	consulBackendDataSnippetPath = "snippets/consul-backend-data.tf"
	layoutSnippetPath            = "snippets/layout.tf"
)

//go:embed snippets
var layoutFiles embed.FS

// AddOptions allows to add option after instance creation
func (instance *renderer) AddOptions(opts ...options.Option) fail.Error {
	for _, v := range opts {
		xerr := v(instance.opts)
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

// IsNull tells if the instance must be considered as a null/zero value
func (instance *renderer) IsNull() bool {
	return instance == nil || instance.mu == nil || instance.opts == nil || instance.config.WorkDir == "" || instance.config.ExecPath == "" || valid.IsNull(instance.scope)
}

// SetEnv sets/replaces an environment var content
func (instance *renderer) SetEnv(key, value string) fail.Error {
	if key = strings.TrimSpace(key); key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.env[key] = value
	return nil
}

// AddEnv adds an environment var (will fail if alreayd there)
func (instance *renderer) AddEnv(key, value string) fail.Error {
	if key = strings.TrimSpace(key); key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	_, ok := instance.env[key]
	if ok {
		return fail.DuplicateError()
	}

	instance.env[key] = value
	return nil
}

// Assemble creates a main.tf file in the appropriate folder
func (instance *renderer) Assemble(ctx context.Context, resources ...api.Resource) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	defer fail.OnExitLogError(ctx, &ferr)

	if valid.IsNull(instance) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNull(resources) {
		return "", fail.InvalidParameterCannotBeNilError("resources")
	}
	if instance.closed {
		return "", fail.NotAvailableError("renderer has been closed")
	}
	if instance.dirty {
		return "", fail.InconsistentError("built more than once without Reset() in between")
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	authOpts, xerr := instance.provider.AuthenticationOptions()
	if xerr != nil {
		return "", xerr
	}

	configOpts, xerr := instance.provider.ConfigurationOptions()
	if xerr != nil {
		return "", xerr
	}

	variables := data.NewMap[string, any]()
	variables["Provider"] = map[string]any{
		"Name":           instance.provider.Name(),
		"Authentication": authOpts,
		"Configuration":  configOpts,
	}
	variables["Terraformer"] = map[string]any{
		"Config": instance.config,
	}

	embeddedFS := instance.provider.EmbeddedFS()
	variables["ProviderDeclaration"], xerr = instance.RealizeSnippet(embeddedFS, instance.provider.TerraformDefinitionSnippet(), variables)
	if xerr != nil {
		return "", xerr
	}

	allAbstracts, xerr := instance.scope.AllResources()
	if xerr != nil {
		return "", xerr
	}
	for _, v := range resources {
		if v != nil {
			uniqueID := v.UniqueID()
			if uniqueID != "" {
				allAbstracts[uniqueID] = v
			}
		}
	}
	resourceContent := data.NewSlice[string](len(allAbstracts))
	for _, r := range allAbstracts {
		lvars := variables.Clone()
		// lvars.Merge(map[string]any{"Resource": r.ToMap()})
		lvars.Merge(map[string]any{"Resource": r})
		lvars["Extra"] = r.Extra()
		content, xerr := instance.RealizeSnippet(embeddedFS, r.TerraformSnippet(), lvars)
		if xerr != nil {
			return "", xerr
		}

		resourceContent = append(resourceContent, content)
	}
	variables["Resources"] = resourceContent

	// render consul backend configuration to store state
	// if remoteStateStorage > 0 {
	lvars := variables.Clone()
	lvars["Consul"] = instance.config.Consul
	content, xerr := instance.RealizeSnippet(layoutFiles, consulBackendSnippetPath, lvars)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	variables["ConsulBackendConfig"] = content

	// VPL: disabled data.terraform_remote_state for now, troubles more than helps
	// content, xerr = instance.RealizeSnippet(layoutFiles, consulBackendDataSnippetPath, lvars)
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return xerr
	// }
	//
	// variables["ConsulBackendData"] = string(content)
	// } else {
	// 	variables["ConsulBackendConfig"] = ""
	// }

	// finally, render the layout
	content, xerr = instance.RealizeSnippet(layoutFiles, layoutSnippetPath, variables)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	instance.dirty = true
	return content, nil
}

// RealizeSnippet generates a file from box template with variables updated
func (instance *renderer) RealizeSnippet(efs embed.FS, filename string, vars map[string]any) (string, fail.Error) {
	if filename == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("filename")
	}

	tmplString, err := efs.ReadFile(filename)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.Wrap(err, "failed to load template")
	}

	tmplCmd, err := template.Parse(filename, string(tmplString))
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.Wrap(err, "failed to parse template")
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Option("missingkey=error").Execute(dataBuffer, vars)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.Wrap(err, "failed to execute  template")
	}

	out := dataBuffer.String()
	return out, nil
}

const mainFilename = "main.tf"

// createFile creates the file in the appropriate path for terraform to execute it
func (instance *renderer) createMainFile(content string) fail.Error {
	instance.lastFilename = filepath.Join(instance.buildPath, mainFilename)
	err := ioutil.WriteFile(instance.lastFilename, []byte(content), 0600)
	if err != nil {
		return fail.Wrap(err, "failed to create terraform file '%s'", instance.lastFilename)
	}

	return nil
}

// Plan calls the terraform Plan command to simulate changes
// returns:
//   - false, *fail.ErrNotFound if the query returns no result
//   - false, fail.Error if the query returns no result
//   - false, nil if no error occurred and no change would be made
//   - true, nil if no error occurred and changes would be made
func (instance *renderer) Plan(ctx context.Context, def string) (_ map[string]tfexec.OutputMeta, _ bool, ferr fail.Error) {
	if valid.IsNull(instance) {
		return nil, false, fail.InvalidInstanceError()
	}
	if def == "" {
		return nil, false, fail.InvalidParameterCannotBeEmptyStringError("def")
	}
	if instance.closed {
		return nil, false, fail.NotAvailableError("renderer has been closed")
	}
	if !instance.dirty {
		return nil, false, fail.InconsistentError("nothing has been built yet")
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	// Creates main.tf file
	xerr := instance.createMainFile(def)
	if xerr != nil {
		return nil, false, xerr
	}

	err := instance.executor.SetEnv(instance.env)
	if err != nil {
		return nil, false, fail.Wrap(err, "failed to set terraform environment")
	}

	xerr = instance.copyTerraformLockFile()
	if xerr != nil {
		return nil, false, xerr
	}
	defer func() {
		derr := instance.saveTerraformLockFile()
		if derr != nil {
			if ferr != nil {
				_ = ferr.AddConsequence(derr)
			} else {
				ferr = derr
			}
		}
	}()

	err = instance.executor.Init(ctx, tfexec.Upgrade(false))
	if err != nil {
		return nil, false, fail.Wrap(err, "failed to execute terraform init")
	}
	logrus.Trace("terraform init ran successfully.")

	// output, err := executor.Validate(ctx)
	// if err != nil {
	// 	return nil, false, fail.Wrap(err, "failed to validate terraform file")
	// }
	// _ = output
	// logrus.Trace("terraform validate ran successfully.")

	success, err := instance.executor.Plan(ctx)
	if err != nil {
		uerr := errors.Unwrap(err)
		rerr := errors.Unwrap(uerr)
		if rerr != nil {
			switch rerr.(type) {
			case *exec.ExitError:
				if strings.Contains(err.Error(), "Your query returned no results") {
					return nil, false, fail.NotFoundError()
				}

			default:
			}
		}

		return nil, false, fail.Wrap(err, "failed to run terraform plan")
	}
	logrus.Trace("terraform plan ran successfully.")

	outputs, err := instance.executor.Output(ctx)
	if err != nil {
		return nil, false, fail.Wrap(err, "failed to gather terraform outputs")
	}

	return outputs, success, nil
}

func (instance *renderer) defaultEnv() map[string]string {
	return map[string]string{"TF_DATA_DIR": instance.config.PluginDir}
}

const terraformLockFile = ".terraform.lock.hcl"

func (instance *renderer) copyTerraformLockFile() fail.Error {
	lockPath := filepath.Join(instance.config.WorkDir, terraformLockFile)

	// check if lock file exist in tenant folder
	_, err := os.Stat(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			instance.saveLockFile = true
			return nil
		}

		return fail.Wrap(err, "failed to stat file '%s'", lockPath)
	}

	copiedLockPath := filepath.Join(instance.buildPath, terraformLockFile)
	_, xerr := utils.CopyFile(lockPath, copiedLockPath)
	if xerr != nil {
		return xerr
	}

	return nil
}

func (instance *renderer) saveTerraformLockFile() fail.Error {
	if instance.saveLockFile {
		lockPath := filepath.Join(instance.buildPath, terraformLockFile)
		copiedLockPath := filepath.Join(instance.config.WorkDir, terraformLockFile)

		_, err := os.Stat(lockPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}

			return fail.Wrap(err, "failed to stat file '%s'", lockPath)
		}

		_, xerr := utils.CopyFile(lockPath, copiedLockPath)
		if xerr != nil {
			return xerr
		}

		instance.saveLockFile = false
	}

	return nil
}

// Apply calls terraform Apply command to operate changes
func (instance *renderer) Apply(ctx context.Context, def string) (_ map[string]tfexec.OutputMeta, ferr fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if def == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("def")
	}
	if instance.closed {
		return nil, fail.NotAvailableError("renderer has been closed")
	}
	if !instance.dirty {
		return nil, fail.InconsistentError("nothing has been built yet")
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	return instance.apply(ctx, def)
}

// apply is the real function that calls terraform Apply command to operate changes, without instance lock
// Called by Apply() and Destroy()
func (instance *renderer) apply(ctx context.Context, def string) (_ map[string]tfexec.OutputMeta, ferr fail.Error) {
	// Allow context cancellation
	select {
	case <-ctx.Done():
		return nil, fail.AbortedError(ctx.Err())
	default:
	}

	// Creates main.tf file
	xerr := instance.createMainFile(def)
	if xerr != nil {
		return nil, xerr
	}

	err := instance.executor.SetEnv(instance.env)
	if err != nil {
		return nil, fail.Wrap(err, "failed to set terraform environment")
	}

	xerr = instance.copyTerraformLockFile()
	if xerr != nil {
		return nil, xerr
	}
	defer func() {
		derr := instance.saveTerraformLockFile()
		if derr != nil {
			if ferr != nil {
				_ = ferr.AddConsequence(derr)
			} else {
				ferr = derr
			}
		}
	}()

	err = instance.executor.Init(ctx, tfexec.Upgrade(false))
	if err != nil {
		return nil, fail.AbortedError(err, "failed to init terraform executor")
	}
	logrus.Trace("terraform init ran successfully.")

	err = instance.executor.Apply(ctx)
	if err != nil {
		uerr := errors.Unwrap(err)
		rerr := errors.Unwrap(uerr)
		if rerr != nil {
			switch rerr.(type) {
			case *exec.ExitError:
				lowered := strings.ToLower(err.Error())
				if strings.Contains(lowered, "your query returned no results") {
					return nil, fail.NotFoundError(err.Error())
				}
				if strings.Contains(lowered, "your query returned more than one result") {
					return nil, fail.DuplicateError(err.Error())
				}
				if strings.Contains(lowered, "incorrect attribute value type") {
					return nil, fail.SyntaxError(err.Error())
				}
				if strings.Contains(lowered, "configuration is invalid") {
					return nil, fail.SyntaxError(err.Error())
				}
			default:
			}

			return nil, fail.Wrap(err, "terraform apply failed")
		}
	}
	logrus.Trace("terraform apply ran successfully.")

	outputs, err := instance.executor.Output(ctx)
	if err != nil {
		return nil, fail.Wrap(err, "failed to gather terraform outputs")
	}

	return outputs, nil
}

// Destroy calls terraform Destroy command to operate changes
func (instance *renderer) Destroy(ctx context.Context, def string, opts ...options.Option) (ferr fail.Error) {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}
	if def == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("def")
	}
	if instance.closed {
		return fail.NotAvailableError("renderer has been closed")
	}
	if !instance.dirty {
		return fail.InconsistentError("nothing has been built yet")
	}

	o, xerr := options.New(opts...)
	if xerr != nil {
		return xerr
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	// If targets are passed as options, we need to narrow the destruct to these targets only
	var err error
	targets := []string{}
	value, xerr := o.Load(api.OptionTargets)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue

		default:
			return xerr
		}
	} else {
		targets, err = lang.Cast[[]string](value)
		if err != nil {
			switch err.(type) {
			case *fail.ErrNotFound:
				// continue
				debug.IgnoreError(err)
			default:
				return fail.Wrap(err)
			}
		}
	}

	if len(targets) == 0 {
		_, err = instance.apply(ctx, def)
		if err != nil {
			return fail.Wrap(err, "failed to apply terraform")
		}
	} else {
		// Creates main.tf file
		xerr = instance.createMainFile(def)
		if xerr != nil {
			return xerr
		}

		err := instance.executor.SetEnv(instance.env)
		if err != nil {
			return fail.Wrap(err, "failed to set terraform environment")
		}

		xerr = instance.copyTerraformLockFile()
		if xerr != nil {
			return xerr
		}
		defer func() {
			derr := instance.saveTerraformLockFile()
			if derr != nil {
				if ferr != nil {
					_ = ferr.AddConsequence(derr)
				} else {
					ferr = derr
				}
			}
		}()

		err = instance.executor.Init(ctx, tfexec.Upgrade(false))
		if err != nil {
			return fail.Wrap(err, "failed to init terraform executor")
		}

		logrus.Trace("terraform init ran successfully.")

		tfOpts := []tfexec.DestroyOption{}
		for _, v := range targets {
			tfOpts = append(tfOpts, tfexec.Target(v))
		}
		err = instance.executor.Destroy(ctx, tfOpts...)
		if err != nil {
			return fail.Wrap(err, "failed to apply terraform")
		}
		logrus.Trace("terraform destroy ran successfully.")
	}

	return nil
}

// // Import imports existing resource in local state file
// func (instance *renderer) Import(ctx context.Context, resourceAddress, id string) (ferr fail.Error) {
// 	if valid.IsNull(instance) {
// 		return fail.InvalidInstanceError()
// 	}
// 	if instance.closed {
// 		return fail.NotAvailableError("renderer has been closed")
// 	}
// 	if !instance.dirty {
// 		return fail.InconsistentError("nothing has been built yet")
// 	}
//
// 	instance.mu.Lock()
// 	defer instance.mu.Unlock()
//
// 	err := instance.executor.SetEnv(instance.env)
// 	if err != nil {
// 		return fail.Wrap(err, "failed to set terraform environment")
// 	}
//
// 	xerr := instance.copyTerraformLockFile()
// 	if xerr != nil {
// 		return xerr
// 	}
// 	defer func() {
// 		derr := instance.saveTerraformLockFile()
// 		if derr != nil {
// 			if ferr != nil {
// 				_ = ferr.AddConsequence(derr)
// 			} else {
// 				ferr = derr
// 			}
// 		}
// 	}()
//
// 	err = instance.executor.Init(ctx, tfexec.Upgrade(false))
// 	if err != nil {
// 		return fail.Wrap(err, "failed to init terraform executor")
// 	}
// 	logrus.Trace("terraform init ran successfully.")
//
// 	// output, err := executor.Validate(ctx)
// 	// if err != nil {
// 	// 	return fail.Wrap(err, "failed to validate terraform file")
// 	// }
// 	// _ = output
// 	// logrus.Trace("terraform validate ran successfully.")
//
// 	err = instance.executor.Import(ctx, resourceAddress, id, tfexec.AllowMissingConfig(true))
// 	if err != nil {
// 		if strings.Contains(err.Error(), "Resource already managed") {
// 			return fail.DuplicateError()
// 		}
// 		if strings.Contains(err.Error(), "Cannot import non-existent remote object") {
// 			return fail.NotFoundError()
// 		}
// 		return fail.Wrap(err, "failed to apply terraform")
// 	}
// 	logrus.Trace("terraform import ran successfully.")
//
// 	return nil
// }

func (instance *renderer) State(ctx context.Context) (_ *tfjson.State, ferr fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if instance.closed {
		return nil, fail.NotAvailableError("renderer is closed")
	}
	if !instance.dirty {
		return nil, fail.InconsistentError("nothing has been built yet")
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	state, err := instance.executor.Show(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "Resource already managed") {
			return nil, fail.DuplicateError()
		}

		return nil, fail.Wrap(err, "failed to apply terraform")
	}
	logrus.Trace("terraform state show ran successfully.")

	return state, nil
}

// Reset cleans up instance to be reused
func (instance *renderer) Reset() fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	if instance.buildPath != "" {
		err := os.RemoveAll(instance.buildPath)
		if err != nil {
			return fail.Wrap(err)
		}

		err = os.MkdirAll(filepath.Dir(instance.buildPath), 0700)
		if err != nil {
			return fail.Wrap(err, "failed to create temporary folder")
		}
	}

	instance.lastFilename = ""
	instance.dirty = false
	return nil
}

// Close terminates instance and clean things up for good
func (instance *renderer) Close() fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	if instance.buildPath != "" {
		var err error
		if global.Settings.Debug {
			err = os.Rename(instance.buildPath, instance.buildPath+".closed")
		} else {
			err = os.RemoveAll(instance.buildPath)
		}
		if err != nil {
			return fail.Wrap(err)
		}
	}

	instance.buildPath = ""
	instance.lastFilename = ""
	instance.closed = true
	return nil
}

// WorkDir returns the path where the renderer puts its production
func (instance *renderer) WorkDir() (string, fail.Error) {
	if valid.IsNull(instance) {
		return "", fail.InvalidInstanceError()
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	return instance.buildPath, nil
}
