package terraform

import (
	"bytes"
	"context"
	"embed"
	"io/ioutil"
	"path/filepath"

	"github.com/hashicorp/terraform-exec/tfexec"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type ResourceCore struct {
	name    string // contains the name of the resource
	snippet string // contains the snippet to use to configure the resource
}

// NewResourceCore creates a new instance of ResourceCore
func NewResourceCore(name string) ResourceCore {
	return ResourceCore{name: name}
}

func (rc ResourceCore) Snippet() string {
	return rc.snippet
}

// summoner is an implementation of Summoner interface
type summoner struct {
	workDir  string // folder where terraform will find configuration files and more
	execPath string // execution path of terraform binary
}

// NewSummoner instantiates a terraform file builder that will put file in 'workDir'
func NewSummoner(workDir string, execPath string) (*summoner, fail.Error) {
	if workDir == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("workDir")
	}
	if execPath == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("execPath")
	}

	out := &summoner{
		workDir:  workDir,
		execPath: execPath,
	}
	return out, nil
}

// IsNull tells if the instance must be considered as a null/zero value
func (b *summoner) IsNull() bool {
	return b == nil || b.workDir == "" || b.execPath == ""
}

// CreateMain creates a main.tf file in the appropriate folder
func (b *summoner) CreateMain(provider ProviderInternals, resource Resource) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(b) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNull(provider) {
		return fail.InvalidParameterError("provider", "cannot be empty provider")
	}
	if valid.IsNil(resource) {
		return fail.InvalidParameterCannotBeNilError("resource")
	}

	variables := map[string]any{}
	variables["provider"] = provider
	variables["Resource"] = resource

	// render the resource
	var xerr fail.Error
	variables["Resources"], xerr = b.realizeTemplate(provider.GetEmbeddedFS(), resource.Snippet(), variables)
	if xerr != nil {
		return xerr
	}

	// render provider configurations
	variables["ProviderConfigurations"], xerr = b.realizeTemplate(provider.GetEmbeddedFS(), provider.Snippet(), variables)
	if xerr != nil {
		return xerr
	}

	// finally, renders the layout
	content, xerr := b.realizeTemplate(provider.GetEmbeddedFS(), "snippets/layout.tf.template", variables)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Creates main.tf file
	xerr = b.createMainFile(content)
	if xerr != nil {
		return xerr
	}

	return nil
}

// realizeTemplate generates a file from box template with variables updated
func (b summoner) realizeTemplate(efs embed.FS, filename string, vars map[string]interface{}) ([]byte, fail.Error) {
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
func (b summoner) createMainFile(content []byte) fail.Error {
	path := filepath.Join(b.workDir, mainFilename)
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
func (b summoner) Plan(ctx context.Context) (bool, fail.Error) {
	tf, err := tfexec.NewTerraform(b.workDir, b.execPath)
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
func (b summoner) Apply(ctx context.Context) (any, fail.Error) {
	tf, err := tfexec.NewTerraform(b.workDir, b.execPath)
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
func (b summoner) Destroy(ctx context.Context) fail.Error {
	tf, err := tfexec.NewTerraform(b.workDir, b.execPath)
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
