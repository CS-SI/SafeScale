package operations

import (
	"context"
	"errors"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sanity-io/litter"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
)

func NewTerraformBucket(svc iaas.Service) (*TfBucket, fail.Error) {
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

	return &TfBucket{
		svc:                         svc,
		terraformExecutableFullPath: tops.ExecutablePath,
		terraformWorkingDirectory:   tops.WorkPath,
	}, nil
}

type TfBucket struct {
	svc iaas.Service

	terraformExecutableFullPath string
	terraformWorkingDirectory   string

	StorageAccount string
	Name           string
	Identity       string
}

func (t TfBucket) IsNull() bool {
	return false
}

func (t TfBucket) Alter(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfBucket) BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfBucket) Deserialize(ctx context.Context, buf []byte) fail.Error {
	return fail.NewError("useless method")
}

func (t TfBucket) Inspect(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfBucket) Read(ctx context.Context, ref string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfBucket) ReadByID(ctx context.Context, id string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfBucket) Reload(ctx context.Context) fail.Error {
	return fail.NewError("useless method")
}

func (t TfBucket) Sdump(ctx context.Context) (string, fail.Error) {
	return litter.Sdump(t), nil
}

func (t TfBucket) Service() iaas.Service {
	return t.svc
}

func (t TfBucket) GetID() (string, error) {
	return t.Identity, nil
}

func (t TfBucket) Exists(ctx context.Context) (bool, fail.Error) {
	return true, nil
}

func (t TfBucket) GetName() string {
	return t.Name
}

func (t TfBucket) Browse(ctx context.Context, callback func(bucket *abstract.ObjectStorageBucket) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t *TfBucket) Create(ctx context.Context, name string) fail.Error {
	err := renderTerraformBucketFromFiles(ctx, t.svc, t.terraformWorkingDirectory, name)
	if err != nil {
		return fail.ConvertError(err)
	}

	cleanup, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		cerr := cleanup()
		if cerr != nil {
			return fail.NewErrorList([]error{err, cerr})
		}
		return fail.ConvertError(err)
	}

	t.Name = name

	// first, read terraform status
	tfstate, xerr := t.svc.GetTerraformState(context.Background())
	if xerr != nil {
		return xerr
	}

	_, xerr = t.svc.ExportFromState(ctx, abstract.ObjectStorageBucketResource, tfstate, t, name)
	if xerr != nil {
		return fail.Wrap(xerr, "failure exporting from terraform state")
	}

	return nil
}

func (t TfBucket) Delete(ctx context.Context) fail.Error {
	// now remove the disk
	diskFile := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("bucket-%s.tf", t.Name))
	// if file does not exist, consider it done
	if _, err := os.Stat(diskFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fail.ConvertError(err)
	}

	err := os.Remove(diskFile)
	if err != nil {
		return fail.ConvertError(err)
	}

	// Run apply
	cleaner, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		defer func() {
			issue := cleaner()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return fail.Wrap(err, "error running terraform apply")
	}

	return nil
}

func (t TfBucket) Mount(ctx context.Context, hostname string, path string) fail.Error {
	//TODO implement me
	panic("implement me")
}

func (t TfBucket) ToProtocol(ctx context.Context) (*protocol.BucketResponse, fail.Error) {
	return &protocol.BucketResponse{
		Name:   t.Name,
		Mounts: nil, // TODO: fix this
	}, nil
}

func (t TfBucket) Unmount(ctx context.Context, hostname string) fail.Error {
	//TODO implement me
	panic("implement me")
}
