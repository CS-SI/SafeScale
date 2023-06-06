package operations

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	capi "github.com/hashicorp/consul/api"
	"github.com/sanity-io/litter"
	"os"
	"path/filepath"
)

func NewTerraformLabel(svc iaas.Service) (*TfLabel, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	inctx := context.Background()
	cfg, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "error recovering cfg")
	}

	maybe, there := cfg.Get("TerraformCfg")
	if !there {
		return nil, fail.NewError("terraform configuration not found")
	}

	tops, ok := maybe.(stacks.TerraformOptions)
	if !ok {
		return nil, fail.NewError("unexpected cast problem")
	}

	return &TfLabel{
		svc:                         svc,
		terraformExecutableFullPath: tops.ExecutablePath,
		terraformWorkingDirectory:   tops.WorkPath,
	}, nil
}

func LoadTerraformLabels(inctx context.Context, svc iaas.Service) ([]*TfLabel, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	cfg, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "error recovering cfg")
	}

	maybe, there := cfg.Get("TerraformCfg")
	if !there {
		return nil, fail.NewError("terraform configuration not found")
	}

	tops, ok := maybe.(stacks.TerraformOptions)
	if !ok {
		return nil, fail.NewError("unexpected cast problem")
	}

	var labels []KeyValueTag
	var tfLabels []*TfLabel
	var tpContent []byte

	// also add this to a global tags.json file
	tp := filepath.Join(tops.WorkPath, "tags.json")
	// does the file exist ?
	if _, err := os.Stat(tp); err == nil {
		tpContent, err = os.ReadFile(tp)
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		// if the file exists, we read it
		err = json.Unmarshal(tpContent, &labels)
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		for _, label := range labels {
			label := label
			tfLabel, err := NewTerraformLabel(svc)
			if err != nil {
				return nil, fail.ConvertError(err)
			}
			tfLabel.impl = &label
			tfLabels = append(tfLabels, tfLabel)
		}

		return tfLabels, nil
	}

	return nil, fail.NewError("no labels found")
}

func LoadTerraformLabel(inctx context.Context, svc iaas.Service, ref string) (*TfLabel, fail.Error) {
	theLabels, err := LoadTerraformLabels(inctx, svc)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	for _, label := range theLabels {
		if label.GetName() == ref {
			return label, nil
		}
	}

	return nil, fail.NewError("label not found")
}

type TfLabel struct {
	svc  iaas.Service
	impl *KeyValueTag

	terraformExecutableFullPath string
	terraformWorkingDirectory   string
}

func (t TfLabel) IsNull() bool {
	return false
}

func (t TfLabel) Alter(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfLabel) BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfLabel) Deserialize(ctx context.Context, buf []byte) fail.Error {
	return fail.NewError("useless method")
}

func (t TfLabel) Inspect(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfLabel) Read(ctx context.Context, ref string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfLabel) ReadByID(ctx context.Context, id string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfLabel) Reload(ctx context.Context) fail.Error {
	return fail.NewError("useless method")
}

func (t TfLabel) Sdump(ctx context.Context) (string, fail.Error) {
	return litter.Sdump(t), nil
}

func (t TfLabel) Service() iaas.Service {
	return t.svc
}

func (t TfLabel) GetID() (string, error) {
	if t.impl == nil {
		return "", fmt.Errorf("label not initialized")
	}

	return t.impl.GetId(), nil
}

func (t TfLabel) GetName() string {
	return t.impl.GetKey()
}

func (t TfLabel) BindToHost(ctx context.Context, hostInstance resources.Host, value string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfLabel) Browse(ctx context.Context, callback func(*abstract.Label) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t *TfLabel) Create(ctx context.Context, name string, hasDefault bool, defaultValue string) fail.Error {
	if hasDefault {
		var err error
		t.impl, err = NewTfLabel(name, defaultValue)
		if err != nil {
			return fail.ConvertError(err)
		}
	} else {
		var err error
		t.impl, err = NewTfTag(name)
		if err != nil {
			return fail.ConvertError(err)
		}
	}

	// this is quite unusual, we have to store the tag/label as a json file
	// in the working directory of terraform
	// this is because terraform does not support labels/tags
	// and we need to store them somewhere
	// so we store them in a json file

	// so, let's marshal t.impl and put this in content
	content, err := json.Marshal(t.impl)
	if err != nil {
		return fail.ConvertError(err)
	}

	// then save content in a tag file
	fp := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("tag-%s.json", name))
	if _, err = os.Stat(fp); err == nil {
		return fail.ConvertError(fmt.Errorf("tag %s already exists", name))
	}

	err = os.WriteFile(fp, content, 0644)
	if err != nil {
		return fail.ConvertError(err)
	}

	var labels []KeyValueTag
	var tpContent []byte

	// also add this to a global tags.json file
	tp := filepath.Join(t.terraformWorkingDirectory, "tags.json")
	// does the file exist ?
	if _, err := os.Stat(tp); err == nil {
		tpContent, err = os.ReadFile(tp)
		if err != nil {
			return fail.ConvertError(err)
		}

		// if the file exists, we read it
		err = json.Unmarshal(tpContent, &labels)
		if err != nil {
			return fail.ConvertError(err)
		}
	}

	// do not add duplicates
	found := false
	for _, l := range labels {
		if l.GetKey() == t.impl.GetKey() {
			found = true
			break
		}
	}
	if !found {
		labels = append(labels, *t.impl)
	}

	content, err = json.Marshal(labels)
	if err != nil {
		return fail.ConvertError(err)
	}
	err = os.WriteFile(filepath.Join(t.terraformWorkingDirectory, "tags.json"), content, 0644)
	if err != nil {
		return fail.ConvertError(err)
	}

	otherCfg, xerr := t.svc.GetConfigurationOptions(ctx)
	if xerr != nil {
		return fail.ConvertError(fmt.Errorf("error getting configuration options: %w", xerr))
	}

	var terraformCfg stacks.TerraformOptions
	maybe, ok := otherCfg.Get("TerraformCfg")
	if ok {
		terraformCfg, ok = maybe.(stacks.TerraformOptions)
		if !ok {
			return fail.ConvertError(fmt.Errorf("error getting terraform configuration options: %w", xerr))
		}
	}

	err = uploadToConsul(ctx, terraformCfg.ConsulURL, "tags.json", content)
	if err != nil {
		return fail.ConvertError(err)
	}

	return nil
}

func uploadToConsul(ctx context.Context, curl string, s string, content []byte) error {
	// Get a new client
	client, err := capi.NewClient(&capi.Config{
		Address: curl,
		Scheme:  "http",
	})
	if err != nil {
		return fmt.Errorf("failed to create consul client: %w", err)
	}

	// Get a handle to the KV API
	kv := client.KV()

	// PUT a new KV pair
	p := &capi.KVPair{Key: fmt.Sprintf("ourkv/%s", s), Value: content}
	_, err = kv.Put(p, nil)
	if err != nil {
		return fmt.Errorf("failed to put KV pair '%s': %w", fmt.Sprintf("ourkv/%s", s), err)
	}

	// Lookup the pair
	_, _, err = kv.Get(fmt.Sprintf("ourkv/%s", s), nil)
	if err != nil {
		return fmt.Errorf("failed to get KV pair '%s': %w", fmt.Sprintf("ourkv/%s", s), err)
	}
	return nil
}

func (t TfLabel) Delete(ctx context.Context) fail.Error {
	// then save content in a tag file
	fp := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("tag-%s.json", t.GetName()))
	_ = os.Remove(fp)

	var labels []KeyValueTag
	var newLabels []KeyValueTag
	var tpContent []byte

	// also add this to a global tags.json file
	tp := filepath.Join(t.terraformWorkingDirectory, "tags.json")
	// does the file exist ?
	if _, err := os.Stat(tp); err == nil {
		tpContent, err = os.ReadFile(tp)
		if err != nil {
			return fail.ConvertError(err)
		}

		// if the file exists, we read it
		err = json.Unmarshal(tpContent, &labels)
		if err != nil {
			return fail.ConvertError(err)
		}
	}

	for _, l := range labels {
		if l.GetKey() != t.impl.GetKey() {
			newLabels = append(newLabels, l)
		}
	}

	content, err := json.Marshal(newLabels)
	if err != nil {
		return fail.ConvertError(err)
	}
	err = os.WriteFile(filepath.Join(t.terraformWorkingDirectory, "tags.json"), content, 0644)
	if err != nil {
		return fail.ConvertError(err)
	}

	otherCfg, xerr := t.svc.GetConfigurationOptions(ctx)
	if xerr != nil {
		return fail.ConvertError(fmt.Errorf("error getting configuration options: %w", xerr))
	}

	var terraformCfg stacks.TerraformOptions
	maybe, ok := otherCfg.Get("TerraformCfg")
	if ok {
		terraformCfg, ok = maybe.(stacks.TerraformOptions)
		if !ok {
			return fail.ConvertError(fmt.Errorf("error getting terraform configuration options: %w", xerr))
		}
	}

	err = uploadToConsul(ctx, terraformCfg.ConsulURL, "tags.json", content)
	if err != nil {
		return fail.ConvertError(err)
	}

	return nil
}

func (t TfLabel) IsTag(ctx context.Context) (bool, fail.Error) {
	return !t.impl.WithDefaultValue, nil
}

func (t TfLabel) DefaultValue(ctx context.Context) (string, fail.Error) {
	if t.impl == nil {
		return "", fail.InvalidInstanceError()
	}
	a, b := t.impl.GetValue()
	if b != nil {
		return "", fail.ConvertError(b)
	}
	return a, nil
}

func (t TfLabel) ToProtocol(ctx context.Context, withHosts bool) (*protocol.LabelInspectResponse, fail.Error) {
	if !t.impl.HasDefaultValue() {
		return &protocol.LabelInspectResponse{
			Id:         t.impl.GetId(),
			Name:       t.impl.GetKey(),
			HasDefault: t.impl.WithDefaultValue,
		}, nil
	}

	return &protocol.LabelInspectResponse{
		Id:           t.impl.GetId(),
		Name:         t.impl.GetKey(),
		HasDefault:   t.impl.WithDefaultValue,
		DefaultValue: *t.impl.Value,
		Value:        *t.impl.Value,
	}, nil
}

func (t TfLabel) UnbindFromHost(ctx context.Context, hostInstance resources.Host) fail.Error {
	return fail.NewError("useless method")
}
