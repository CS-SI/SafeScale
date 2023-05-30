package operations

import (
	"context"
	"errors"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sanity-io/litter"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strings"
)

func NewTerraformVolume(svc iaas.Service) (*TfVolume, fail.Error) {
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

	return &TfVolume{
		svc:                         svc,
		terraformExecutableFullPath: tops.ExecutablePath,
		terraformWorkingDirectory:   tops.WorkPath,
		Tags:                        make(map[string]string),
	}, nil
}

type TfVolume struct {
	svc iaas.Service

	Identity string
	Name     string
	speed    volumespeed.Enum
	Size     int32

	attachments []*protocol.VolumeAttachmentResponse
	kvs         []*protocol.KeyValue

	terraformExecutableFullPath string
	terraformWorkingDirectory   string
	Location                    string
	Tags                        map[string]string
}

func (t TfVolume) IsNull() bool {
	return false
}

func (t TfVolume) Alter(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfVolume) BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfVolume) Deserialize(ctx context.Context, buf []byte) fail.Error {
	return fail.NewError("useless method")
}

func (t TfVolume) Inspect(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method") // metadata related
}

func (t TfVolume) Read(ctx context.Context, ref string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfVolume) ReadByID(ctx context.Context, id string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfVolume) Reload(ctx context.Context) fail.Error {
	return fail.NewError("useless method")
}

func (t TfVolume) Sdump(ctx context.Context) (string, fail.Error) {
	return litter.Sdump(t), nil
}

func (t TfVolume) Service() iaas.Service {
	return t.svc
}

func (t TfVolume) GetID() (string, error) {
	return t.Identity, nil
}

func (t TfVolume) Exists(ctx context.Context) (bool, fail.Error) {
	return true, nil
}

func (t TfVolume) GetName() string {
	return t.Name
}

func (t TfVolume) Attach(ctx context.Context, host resources.Host, path, format string, doNotFormat, doNotMount bool) fail.Error {
	if !doNotFormat {
		return fail.InvalidRequestError("formatting is not supported")
	}
	if !doNotMount {
		return fail.InvalidRequestError("mounting is not supported")
	}

	// Create the attachment
	err := renderTerraformDiskAttachmentFromFiles(ctx, t.svc, t.terraformWorkingDirectory, t, host)
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

func (t TfVolume) Browse(ctx context.Context, callback func(*abstract.Volume) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t *TfVolume) Create(ctx context.Context, req abstract.VolumeRequest) fail.Error {
	err := renderTerraformVolumeFromFiles(ctx, t.svc, t.terraformWorkingDirectory, req)
	if err != nil {
		return fail.ConvertError(err)
	}

	workPath := t.terraformWorkingDirectory

	cleanup, err := createTerraformVolume(ctx, t.svc, t.terraformExecutableFullPath, workPath, req)
	if err != nil {
		cerr := cleanup()
		if cerr != nil {
			return fail.NewErrorList([]error{err, cerr})
		}
		return fail.ConvertError(err)
	}

	t.Name = req.Name

	// first, read terraform status
	tfstate, xerr := t.svc.GetTerraformState(context.Background())
	if xerr != nil {
		return xerr
	}

	_, xerr = t.svc.ExportFromState(ctx, abstract.VolumeResource, tfstate, t, req.Name)
	if xerr != nil {
		return fail.Wrap(xerr, "failure exporting from terraform state")
	}

	return nil
}

func (t TfVolume) Delete(ctx context.Context) fail.Error {
	atts, xerr := t.GetAttachments(ctx)
	if xerr != nil {
		return xerr
	}
	if atts != nil {
		if len(atts.Hosts) > 0 {
			return fail.InvalidRequestError("volume is still attached to hosts, please detach it first")
		}
	}

	// delete all files beginning with "attachment-" and ending with "-diskname"
	file, err := os.Open(t.terraformWorkingDirectory)
	if err != nil {
		return fail.ConvertError(err)
	}
	defer file.Close()
	names, err := file.Readdirnames(0)
	if err != nil {
		return fail.ConvertError(err)
	}

	for _, name := range names {
		if strings.HasPrefix(name, "attachment-") && strings.HasSuffix(name, fmt.Sprintf("-%s", t.Name)) {
			err := os.Remove(name)
			if err != nil {
				return fail.ConvertError(err)
			}
		}
	}

	// now remove the disk
	diskFile := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("disk-%s.tf", t.Name))
	// if file does not exist, consider it done
	if _, err := os.Stat(diskFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fail.ConvertError(err)
	}

	err = os.Remove(diskFile)
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

func (t TfVolume) Detach(ctx context.Context, host resources.Host) fail.Error {
	// remove attachment file
	attachmentFile := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("attachment-%s-%s.tf", host.GetName(), t.Name))

	// if file does not exist, consider it done
	if _, err := os.Stat(attachmentFile); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fail.ConvertError(err)
	}

	// if file named attachmentFile exists, delete it
	err := os.Remove(attachmentFile)
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

func (t TfVolume) GetAttachments(ctx context.Context) (*propertiesv1.VolumeAttachments, fail.Error) {
	// first, read terraform status
	tfstate, xerr := t.svc.GetTerraformState(ctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, nil
		default:
			return nil, xerr
		}
	}

	empty := &TfVolumeAttachment{}
	tats, xerr := t.svc.ExportFromState(ctx, abstract.VolumeAttachmentResource, tfstate, empty, "")
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failure exporting from terraform state")
	}
	atts := tats.([]*TfVolumeAttachment) // nolint

	getNameFromId := func(id string) string {
		if !strings.Contains(id, "/") {
			return id
		}
		frag := strings.Split(id, "/")
		return frag[len(frag)-1]
	}

	hids := make(map[string]string)
	for _, tat := range atts {
		if tat.AttachedDiskId == t.Identity {
			hids[tat.AttachedHostId] = getNameFromId(tat.AttachedHostId)
		}
	}

	return &propertiesv1.VolumeAttachments{
		Hosts: hids,
	}, nil
}

func (t TfVolume) GetSize(ctx context.Context) (int, fail.Error) {
	return int(t.Size), nil
}

func (t TfVolume) GetSpeed(ctx context.Context) (volumespeed.Enum, fail.Error) {
	return volumespeed.Ssd, nil
}

func (t TfVolume) ToProtocol(ctx context.Context) (*protocol.VolumeInspectResponse, fail.Error) {
	atts, xerr := t.GetAttachments(ctx)
	if xerr != nil {
		return nil, xerr
	}

	var atr []*protocol.VolumeAttachmentResponse
	if atts != nil {
		for k, v := range atts.Hosts {
			atr = append(atr, &protocol.VolumeAttachmentResponse{
				Host: &protocol.Reference{
					Id:   v,
					Name: k,
				},
			})
		}
	}

	return &protocol.VolumeInspectResponse{
		Id:          t.Identity,
		Name:        t.Name,
		Speed:       protocol.VolumeSpeed_VS_SSD,
		Size:        t.Size,
		Attachments: atr,
		Kvs:         toKvs(t.Tags),
	}, nil
}
