package operations

import (
	"context"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sanity-io/litter"
)

func NewTerraformShare(svc iaas.Service) (*TfShare, fail.Error) {
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

	return &TfShare{
		svc:                         svc,
		terraformExecutableFullPath: tops.ExecutablePath,
		terraformWorkingDirectory:   tops.WorkPath,
	}, nil
}

type TfShare struct {
	svc iaas.Service

	name     string
	identity string
	path     string
	machines []string

	terraformExecutableFullPath string
	terraformWorkingDirectory   string
}

func (t TfShare) IsNull() bool {
	return false
}

func (t TfShare) Alter(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfShare) BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfShare) Deserialize(ctx context.Context, buf []byte) fail.Error {
	return fail.NewError("useless method")
}

func (t TfShare) Inspect(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfShare) Read(ctx context.Context, ref string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfShare) ReadByID(ctx context.Context, id string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfShare) Reload(ctx context.Context) fail.Error {
	return fail.NewError("useless method")
}

func (t TfShare) Sdump(ctx context.Context) (string, fail.Error) {
	return litter.Sdump(t), nil
}

func (t TfShare) Service() iaas.Service {
	return t.svc
}

func (t TfShare) GetID() (string, error) {
	return t.identity, nil
}

func (t TfShare) Exists(ctx context.Context) (bool, fail.Error) {
	return true, nil
}

func (t TfShare) GetName() string {
	return t.name
}

func (t TfShare) Browse(ctx context.Context, callback func(hostName string, shareID string) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfShare) Create(ctx context.Context, shareName string, host resources.Host, path string, options string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (t TfShare) Delete(ctx context.Context) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (t TfShare) GetServer(ctx context.Context) (resources.Host, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (t TfShare) Mount(ctx context.Context, host resources.Host, path string, withCache bool) (*propertiesv1.HostRemoteMount, fail.Error) {
	//TODO implement me
	panic("implement me")
}

func (t TfShare) Unmount(ctx context.Context, host resources.Host) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (t TfShare) ToProtocol(ctx context.Context) (*protocol.ShareMountList, fail.Error) {
	//TODO implement me
	panic("implement me")
}
