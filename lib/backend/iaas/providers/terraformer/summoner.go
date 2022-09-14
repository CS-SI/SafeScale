package terraformer

import (
	"bytes"
	"context"
	"embed"
	"io/ioutil"
	"path/filepath"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/hashicorp/terraform-exec/tfexec"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type Configuration struct {
	WorkDir       string
	ExecPath      string
	ConsulBackend struct {
		Path string // "safescale/terraformstate/{{ or .CurrentOrganization "default" }}/{{ or .CurrentProject "default" }}"<
		Use  bool
	}
}

// summoner is an implementation of Summoner interface
type summoner struct {
	config Configuration
}

// NewSummoner instantiates a terraform file builder that will put file in 'workDir'
func NewSummoner(conf Configuration) (*summoner, fail.Error) {
	if conf.WorkDir == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("workDir")
	}
	if conf.ExecPath == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("execPath")
	}

	out := &summoner{conf}
	return out, nil
}

// IsNull tells if the instance must be considered as a null/zero value
func (instance *summoner) IsNull() bool {
	return instance == nil || instance.config.WorkDir == "" || instance.config.ExecPath == ""
}

// Build creates a main.tf file in the appropriate folder
func (instance *summoner) Build(provider ProviderInternals, resources ...Resource) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNull(provider) {
		return fail.InvalidParameterError("provider", "cannot be empty provider")
	}
	if valid.IsNull(resources) {
		return fail.InvalidParameterCannotBeNilError("resources")
	}

	variables := data.NewMap()
	variables["Provider"] = provider

	// render the resources
	var (
		xerr fail.Error
	)
	resourceContent := make([][]byte, len(resources), 0)
	for _, r := range resources {
		lvars := variables.Clone()
		lvars.Merge(r.ToMap())
		content, xerr := instance.realizeTemplate(provider.EmbeddedFS(), r.Snippet(), lvars)
		if xerr != nil {
			return xerr
		}

		resourceContent = append(resourceContent, content)
	}
	variables["Resources"] = resourceContent

	// render provider configuration
	variables["ProviderConfiguration"], xerr = instance.realizeTemplate(provider.EmbeddedFS(), provider.Snippet(), variables)
	if xerr != nil {
		return xerr
	}

	// render optional consul backend configuration
	if instance.config.ConsulBackend.Use {
		lvars := variables.Clone()
		lvars["ConsulBackend"] = instance.config.ConsulBackend
		content, xerr := instance.realizeTemplate(provider.EmbeddedFS(), "snippets/consul-backend.tf.template", variables)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		variables["ConsulBackend"] = content

		content, xerr = instance.realizeTemplate(provider.EmbeddedFS(), "snippets/consul-backend-data.tf.template", variables)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		variables["ConsulBackendData"] = content
	}

	// finally, render the layout
	content, xerr := instance.realizeTemplate(provider.EmbeddedFS(), "snippets/layout.tf.template", variables)
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
func (instance summoner) realizeTemplate(efs embed.FS, filename string, vars map[string]interface{}) ([]byte, fail.Error) {
	tmplString, err := efs.ReadFile(filename)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return nil, fail.Wrap(err, "failed to load template")
	}

	tmplCmd, err := template.Parse(filename, string(tmplString))
	err = debug.InjectPlannedError(err)
	if err != nil {
		return nil, fail.Wrap(err, "failed to parse template")
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Option("missingkey=error").Execute(dataBuffer, vars)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return nil, fail.Wrap(err, "failed to execute  template")
	}

	cmd := dataBuffer.Bytes()
	return cmd, nil
}

const mainFilename = "main.tf"

// createFile creates the file in the appropriate path for terraform to execute it
func (instance summoner) createMainFile(content []byte) fail.Error {
	path := filepath.Join(instance.workDir, mainFilename)
	err := ioutil.WriteFile(path, content, 0)
	if err != nil {
		return fail.Wrap(err, "failed to create main terraform file")
	}

	return nil
}

// Plan calls the terraform Plan command to simulate changes
// returns:
//   - false, fail.Error if an error occurred
//   - false, nil if no error occurred and no change would be made
//   - true, nil if no error occurred and changes would be made
func (instance *summoner) Plan(ctx context.Context) (bool, fail.Error) {
	if valid.IsNull(instance) {
		return false, fail.InvalidInstanceError()
	}

	tf, err := tfexec.NewTerraform(instance.workDir, instance.execPath)
	if err != nil {
		return false, fail.Wrap(err, "failed to instantiate terraform executor")
	}

	err = tf.Init(ctx, tfexec.Upgrade(true))
	if err != nil {
		return false, fail.Wrap(err, "failed to init terraform executor")
	}

	out, err := tf.Plan(ctx)
	if err != nil {
		return false, fail.Wrap(err, "failed to apply terraform")
	}

	return out, nil
}

// Apply calls the terraform Apply command to operate changes
func (instance *summoner) Apply(ctx context.Context) (any, fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidInstanceError()
	}

	tf, err := tfexec.NewTerraform(instance.workDir, instance.execPath)
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

	tf, err := tfexec.NewTerraform(instance.workDir, instance.execPath)
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
