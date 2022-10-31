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

package terraformer

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

	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	uuidpkg "github.com/gofrs/uuid"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api/terraformer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// ProviderUseTerraformer ...
type providerUseTerraformer interface {
	Name() string
	EmbeddedFS() embed.FS
	Snippet() string
}

// summoner is an implementation of Summoner interface
type summoner struct {
	mu           *sync.Mutex
	executor     *tfexec.Terraform
	provider     iaasapi.Provider
	config       terraformerapi.Configuration
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

// NewSummoner instantiates a terraform file builder that will put file in 'workDir'
func NewSummoner(provider iaasapi.Provider, conf terraformerapi.Configuration) (terraformerapi.Summoner, fail.Error) {
	if valid.IsNull(provider) {
		return nil, fail.InvalidInstanceError()
	}
	if conf.WorkDir == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("workDir")
	}
	if conf.ExecPath == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("execPath")
	}
	if _, ok := provider.(providerUseTerraformer); !ok {
		return nil, fail.InconsistentError("missing methods in 'provider' to be used by Summoner")
	}

	out := &summoner{provider: provider, config: conf, mu: &sync.Mutex{}}
	out.env = out.defaultEnv()

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return nil, fail.Wrap(err, "failed to generate uuid")
	}

	out.buildPath = filepath.Join(out.config.WorkDir, uuid.String())
	err = os.MkdirAll(out.buildPath, 0700)
	if err != nil {
		return nil, fail.Wrap(err, "failed to create temporary folder")
	}

	out.executor, err = tfexec.NewTerraform(out.buildPath, out.config.ExecPath)
	if err != nil {
		return nil, fail.Wrap(err, "failed to instantiate terraform executor")
	}

	return out, nil
}

// IsNull tells if the instance must be considered as a null/zero value
func (instance *summoner) IsNull() bool {
	return instance == nil || instance.mu == nil || instance.config.WorkDir == "" || instance.config.ExecPath == ""
}

// SetEnv sets/replaces an environment var content
func (instance *summoner) SetEnv(key, value string) fail.Error {
	if key = strings.TrimSpace(key); key == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	instance.env[key] = value
	return nil
}

// AddEnv adds an environment var (will fail if alreayd there)
func (instance *summoner) AddEnv(key, value string) fail.Error {
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
func (instance *summoner) Assemble(resources ...terraformerapi.Resource) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(instance) {
		return "", fail.InvalidInstanceError()
	}
	if valid.IsNull(resources) {
		return "", fail.InvalidParameterCannotBeNilError("resources")
	}
	if instance.closed {
		return "", fail.NotAvailableError("summoner has been closed")
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
		"Name":           instance.provider.(providerUseTerraformer).Name(),
		"Authentication": authOpts,
		"Configuration":  configOpts,
	}
	variables["Terraformer"] = map[string]any{
		"Config": instance.config,
	}

	// render the resources
	// localStateStorage, remoteStateStorage := 0, 0
	// for _, r := range resources {
	// 	if r.RemoteState() {
	// 		remoteStateStorage++
	// 	} else {
	// 		localStateStorage++
	// 	}
	// }
	// rscCount := len(resources)
	// if remoteStateStorage != rscCount && localStateStorage != rscCount {
	// 	return "", fail.InvalidRequestError("cannot mix resources with remote and local state storage")
	// }

	resourceContent := data.NewSlice[string](len(resources))
	for _, r := range resources {
		lvars := variables.Clone()
		// lvars.Merge(map[string]any{"Resource": r.ToMap()})
		lvars.Merge(map[string]any{"Resource": r})
		content, xerr := instance.realizeTemplate(instance.provider.(providerUseTerraformer).EmbeddedFS(), r.Snippet(), lvars)
		if xerr != nil {
			return "", xerr
		}

		resourceContent = append(resourceContent, content)
	}
	variables["Resources"] = resourceContent

	// render provider configuration
	variables["ProviderDeclaration"], xerr = instance.realizeTemplate(instance.provider.(providerUseTerraformer).EmbeddedFS(), instance.provider.(providerUseTerraformer).Snippet(), variables)
	if xerr != nil {
		return "", xerr
	}

	// render consul backend configuration to store state
	// if remoteStateStorage > 0 {
	lvars := variables.Clone()
	lvars["Consul"] = instance.config.Consul
	content, xerr := instance.realizeTemplate(layoutFiles, consulBackendSnippetPath, lvars)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	variables["ConsulBackendConfig"] = content

	// VPL: disabled data.terraform_remote_state for now, troubles more than helps
	// content, xerr = instance.realizeTemplate(layoutFiles, consulBackendDataSnippetPath, lvars)
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
	content, xerr = instance.realizeTemplate(layoutFiles, layoutSnippetPath, variables)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	instance.dirty = true
	return content, nil
}

// realizeTemplate generates a file from box template with variables updated
func (instance *summoner) realizeTemplate(efs embed.FS, filename string, vars map[string]any) (string, fail.Error) {
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
func (instance *summoner) createMainFile(content string) fail.Error {
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
func (instance *summoner) Plan(ctx context.Context, def string) (_ map[string]tfexec.OutputMeta, _ bool, ferr fail.Error) {
	if valid.IsNull(instance) {
		return nil, false, fail.InvalidInstanceError()
	}
	if def == "" {
		return nil, false, fail.InvalidParameterCannotBeEmptyStringError("def")
	}
	if instance.closed {
		return nil, false, fail.NotAvailableError("summoner has been closed")
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

func (instance *summoner) defaultEnv() map[string]string {
	return map[string]string{
		"TF_DATA_DIR": instance.config.PluginDir,
	}
}

const terraformLockFile = ".terraform.lock.hcl"

func (instance *summoner) copyTerraformLockFile() fail.Error {
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

func (instance *summoner) saveTerraformLockFile() fail.Error {
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
func (instance *summoner) Apply(ctx context.Context, def string) (_ map[string]tfexec.OutputMeta, ferr fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if def == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("def")
	}
	if instance.closed {
		return nil, fail.NotAvailableError("summoner has been closed")
	}
	if !instance.dirty {
		return nil, fail.InconsistentError("nothing has been built yet")
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

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
		return nil, fail.Wrap(err, "failed to init terraform executor")
	}
	logrus.Trace("terraform init ran successfully.")

	// output, err := executor.Validate(ctx)
	// if err != nil {
	// 	return nil, fail.Wrap(err, "failed to validate terraform file")
	// }
	// _ = output
	// logrus.Trace("terraform validate ran successfully.")

	err = instance.executor.Apply(ctx)
	if err != nil {
		uerr := errors.Unwrap(err)
		rerr := errors.Unwrap(uerr)
		if rerr != nil {
			switch rerr.(type) {
			case *exec.ExitError:
				if strings.Contains(err.Error(), "Your query returned no results") {
					return nil, fail.NotFoundError()
				}
				if strings.Contains(err.Error(), "Your query returned more than one result") {
					return nil, fail.DuplicateError()
				}
				if strings.Contains(err.Error(), "Incorrect attribute value type") {
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

// Destroy calls the terraform Destroy command to operate changes
func (instance *summoner) Destroy(ctx context.Context, def string) (ferr fail.Error) {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}
	if def == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("def")
	}
	if instance.closed {
		return fail.NotAvailableError("summoner has been closed")
	}
	if !instance.dirty {
		return fail.InconsistentError("nothing has been built yet")
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	// Creates main.tf file
	xerr := instance.createMainFile(def)
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

	// output, err := executor.Validate(ctx)
	// if err != nil {
	// 	return fail.Wrap(err, "failed to validate terraform file")
	// }
	// _ = output
	// logrus.Trace("terraform validate ran successfully.")

	err = instance.executor.Destroy(ctx)
	if err != nil {
		return fail.Wrap(err, "failed to apply terraform")
	}
	logrus.Trace("terraform destroy ran successfully.")

	return nil
}

// // Import imports existing resource in local state file
// func (instance *summoner) Import(ctx context.Context, resourceAddress, id string) (ferr fail.Error) {
// 	if valid.IsNull(instance) {
// 		return fail.InvalidInstanceError()
// 	}
// 	if instance.closed {
// 		return fail.NotAvailableError("summoner has been closed")
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

// func (instance *summoner) State(ctx context.Context) (_ *tfjson.State, ferr fail.Error) {
// 	if valid.IsNull(instance) {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if instance.closed {
// 		return nil, fail.NotAvailableError("summoner is closed")
// 	}
// 	if !instance.dirty {
// 		return nil, fail.InconsistentError("nothing has been built yet")
// 	}
//
// 	instance.mu.Lock()
// 	defer instance.mu.Unlock()
//
// 	state, err := instance.executor.Show(ctx)
// 	if err != nil {
// 		if strings.Contains(err.Error(), "Resource already managed") {
// 			return nil, fail.DuplicateError()
// 		}
//
// 		return nil, fail.Wrap(err, "failed to apply terraform")
// 	}
// 	logrus.Trace("terraform state show ran successfully.")
//
// 	return state, nil
// }

// Reset cleans up instance to be reused
func (instance *summoner) Reset() fail.Error {
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
func (instance *summoner) Close() fail.Error {
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
