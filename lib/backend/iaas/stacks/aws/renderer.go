package aws

import (
	"context"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	tfjson "github.com/hashicorp/terraform-json"
)

func (s stack) Render(ctx context.Context, kind abstract.Enum, workDir string, options map[string]any) ([]abstract.RenderedContent, fail.Error) {
	return nil, nil
}

func (s stack) GetTerraformState(ctx context.Context) (_ *tfjson.State, ferr fail.Error) {
	return nil, nil
}

func (s stack) ExportFromState(ctx context.Context, kind abstract.Enum, state *tfjson.State, input any, id string) (any, fail.Error) {
	return nil, nil
}
