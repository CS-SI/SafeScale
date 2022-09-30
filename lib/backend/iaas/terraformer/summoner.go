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
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	uuidpkg "github.com/gofrs/uuid"
	"github.com/hashicorp/terraform-exec/tfexec"

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
	provider      iaasapi.Provider
	config        terraformerapi.Configuration
	lastBuildPath string
	mu            *sync.Mutex
}

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
	return out, nil
}

// IsNull tells if the instance must be considered as a null/zero value
func (instance *summoner) IsNull() bool {
	return instance == nil || instance.mu == nil || instance.config.WorkDir == "" || instance.config.ExecPath == ""
}

// Build creates a main.tf file in the appropriate folder
func (instance *summoner) Build(resources ...terraformerapi.Resource) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNull(resources) {
		return fail.InvalidParameterCannotBeNilError("resources")
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	// If previous built file is still referenced in summoner, Cleanup wasn't called as expected
	if instance.lastBuildPath != "" {
		return fail.InvalidRequestError("trying to create a new main.tf file without having cleaned up the Summoner")
	}

	authOpts, xerr := instance.provider.AuthenticationOptions()
	if xerr != nil {
		return xerr
	}

	configOpts, xerr := instance.provider.ConfigurationOptions()
	if xerr != nil {
		return xerr
	}

	variables := data.NewMap()
	variables["Provider"] = map[string]any{
		"Name":           instance.provider.(providerUseTerraformer).Name(),
		"Authentication": authOpts,
		"Configuration":  configOpts,
	}
	variables["Terraformer"] = map[string]any{
		"Config": instance.config,
	}

	// render the resources
	resourceContent := make([]string, len(resources))
	for _, r := range resources {
		lvars := variables.Clone()
		lvars.Merge(map[string]any{"Resource": r.ToMap()})
		content, xerr := instance.realizeTemplate(instance.provider.(providerUseTerraformer).EmbeddedFS(), r.Snippet(), lvars)
		if xerr != nil {
			return xerr
		}

		resourceContent = append(resourceContent, content)
	}
	variables["Resources"] = resourceContent

	// render provider configuration
	variables["ProviderDeclaration"], xerr = instance.realizeTemplate(instance.provider.(providerUseTerraformer).EmbeddedFS(), instance.provider.(providerUseTerraformer).Snippet(), variables)
	if xerr != nil {
		return xerr
	}

	// render optional consul backend configuration
	if instance.config.ConsulBackend.Use {
		lvars := variables.Clone()
		lvars["ConsulBackend"] = instance.config.ConsulBackend
		content, xerr := instance.realizeTemplate(layoutFiles, "snippets/consul-backend.tf.template", variables)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		variables["ConsulBackend"] = content

		content, xerr = instance.realizeTemplate(layoutFiles, "snippets/consul-backend-data.tf.template", variables)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		variables["ConsulBackendData"] = string(content)
	}

	// finally, render the layout
	content, xerr := instance.realizeTemplate(layoutFiles, "snippets/layout.tf.template", variables)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Creates main.tf file
	xerr = instance.createMainFile(content)
	if xerr != nil {
		return xerr
	}

	return nil
}

// realizeTemplate generates a file from box template with variables updated
func (instance summoner) realizeTemplate(efs embed.FS, filename string, vars map[string]any) (string, fail.Error) {
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
	if instance.lastBuildPath != "" {
		return fail.InvalidRequestError("trying to create a new main.tf file without having cleaned up the Summoner environment")
	}

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return fail.Wrap(err, "failed to generate uuid")
	}

	instance.lastBuildPath = filepath.Join(instance.config.WorkDir, uuid.String(), mainFilename)
	err = os.MkdirAll(filepath.Dir(instance.lastBuildPath), 0700)
	if err != nil {
		return fail.Wrap(err, "failed to create temporary folder")
	}

	err = ioutil.WriteFile(instance.lastBuildPath, []byte(content), 0600)
	if err != nil {
		return fail.Wrap(err, "failed to create terraform file '%s'", instance.lastBuildPath)
	}

	return nil
}

// Plan calls the terraform Plan command to simulate changes
// returns:
//   - false, fail.Error if an error occurred
//   - false, nil if no error occurred and no change would be made
//   - true, nil if no error occurred and changes would be made
func (instance *summoner) Plan(ctx context.Context) (map[string]tfexec.OutputMeta, bool, fail.Error) {
	if valid.IsNull(instance) {
		return nil, false, fail.InvalidInstanceError()
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	tf, err := tfexec.NewTerraform(instance.config.WorkDir, instance.config.ExecPath)
	if err != nil {
		return nil, false, fail.Wrap(err, "failed to instantiate terraform executor")
	}

	err = tf.Init(ctx, tfexec.Upgrade(true))
	if err != nil {
		return nil, false, fail.Wrap(err, "failed to init terraform executor")
	}

	success, err := tf.Plan(ctx)
	if err != nil {
		return nil, false, fail.Wrap(err, "failed to apply terraform")
	}

	outputs, err := tf.Output(ctx)
	if err != nil {
		return nil, false, fail.Wrap(err, "failed to gather terraform outputs")
	}

	return outputs, success, nil
}

// Apply calls the terraform Apply command to operate changes
func (instance *summoner) Apply(ctx context.Context) (map[string]tfexec.OutputMeta, fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidInstanceError()
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	tf, err := tfexec.NewTerraform(filepath.Dir(instance.lastBuildPath), instance.config.ExecPath)
	if err != nil {
		return nil, fail.Wrap(err, "failed to instanciate terraform executor")
	}

	err = tf.Init(ctx, tfexec.Upgrade(true))
	if err != nil {
		return nil, fail.Wrap(err, "failed to init terraform executor")
	}

	err = tf.Apply(ctx)
	if err != nil {
		return nil, fail.Wrap(err, "failed to apply terraform")
	}

	outputs, err := tf.Output(ctx)
	if err != nil {
		return nil, fail.Wrap(err, "failed to gather terraform outputs")
	}

	return outputs, nil
}

// Destroy calls the terraform Destroy command to operate changes
func (instance *summoner) Destroy(ctx context.Context) fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	tf, err := tfexec.NewTerraform(instance.config.WorkDir, instance.config.ExecPath)
	if err != nil {
		return fail.Wrap(err, "failed to instanciate terraform executor")
	}

	err = tf.Init(ctx, tfexec.Upgrade(true))
	if err != nil {
		return fail.Wrap(err, "failed to init terraform executor")
	}

	err = tf.Destroy(ctx)
	if err != nil {
		return fail.Wrap(err, "failed to apply terraform")
	}

	return nil
}

func (instance *summoner) Cleanup(ctx context.Context) fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}

	instance.mu.Lock()
	defer instance.mu.Unlock()

	if instance.lastBuildPath != "" {
		err := os.Remove(instance.lastBuildPath)
		if err != nil {
			return fail.Wrap(err)
		}

		instance.lastBuildPath = ""
	}

	return nil
}
