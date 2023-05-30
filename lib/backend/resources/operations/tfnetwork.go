package operations

import (
	"context"
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
	"strings"
)

func NewTerraformNetwork(svc iaas.Service) (*TfNetwork, fail.Error) {
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

	return &TfNetwork{svc: svc, terraformExecutableFullPath: tops.ExecutablePath, terraformWorkingDirectory: tops.WorkPath, Tags: make(map[string]string)}, nil
}

type TfNetwork struct {
	svc                         iaas.Service
	terraformExecutableFullPath string
	terraformWorkingDirectory   string

	Name     string
	Identity string

	netRequest    *abstract.NetworkRequest
	subnetRequest *abstract.SubnetRequest
	CIDR          string
	Tags          map[string]string
	SubnetCidr    string
	SubnetId      string
	SubnetName    string
}

func (t TfNetwork) IsNull() bool {
	return false
}

func (t TfNetwork) Alter(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfNetwork) BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfNetwork) Deserialize(ctx context.Context, buf []byte) fail.Error {
	return fail.NewError("useless method")
}

func (t TfNetwork) Inspect(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfNetwork) Read(ctx context.Context, ref string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfNetwork) ReadByID(ctx context.Context, id string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfNetwork) Reload(ctx context.Context) fail.Error {
	return fail.NewError("useless method")
}

func (t TfNetwork) Sdump(ctx context.Context) (string, fail.Error) {
	return litter.Sdump(t), nil
}

func (t TfNetwork) Service() iaas.Service {
	return t.svc
}

func (t TfNetwork) GetID() (string, error) {
	return t.Name, nil
}

func (t TfNetwork) Exists(ctx context.Context) (bool, fail.Error) {
	return true, nil
}

func (t TfNetwork) GetName() string {
	return t.Name
}

func (t TfNetwork) AbandonSubnet(ctx context.Context, subnetID string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfNetwork) AdoptSubnet(ctx context.Context, subnet resources.Subnet) fail.Error {
	return fail.NewError("useless method")
}

func (t TfNetwork) Browse(ctx context.Context, callback func(*abstract.Network) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t *TfNetwork) Create(ctx context.Context, req *abstract.NetworkRequest, snreq *abstract.SubnetRequest) fail.Error {
	// List all the networks in the state
	nets, xerr := ListTerraformNetworks(ctx, t.svc)
	if xerr != nil {
		return fail.ConvertError(fmt.Errorf("failed to list networks: %w", xerr))
	}
	// make sure the network doesn't already exist
	for _, anet := range nets {
		if anet.GetName() == fmt.Sprintf("network-%s", req.Name) {
			return fail.DuplicateError("network already exists")
		}
	}

	cfg, xerr := t.svc.GetConfigurationOptions(ctx)
	if xerr != nil {
		return fail.Wrap(xerr, "error recovering cfg")
	}

	t.netRequest = req
	t.subnetRequest = snreq

	err := renderTerraformNetworkFromFiles(ctx, t.svc, t.terraformWorkingDirectory, *req)
	if err != nil {
		return fail.ConvertError(err)
	}

	workPath := t.terraformWorkingDirectory

	if snreq.ImageRef == "" {
		snreq.ImageRef = cfg.GetString("DefaultImage")
	}

	// create a {cluster}-rendered.tf file
	err = prepareTerraformNetworkVars(ctx, t.svc, workPath, *req, *snreq)
	if err != nil {
		return fail.ConvertError(err)
	}

	cleanup, err := createTerraformNetwork(ctx, t.svc, t.terraformExecutableFullPath, workPath, *req, *snreq)
	if err != nil {
		cerr := cleanup()
		if cerr != nil {
			return fail.NewErrorList([]error{err, cerr})
		}
		return fail.ConvertError(err)
	}

	// first, read terraform status
	tfstate, xerr := t.svc.GetTerraformState(context.Background())
	if xerr != nil {
		return xerr
	}

	_, xerr = t.svc.ExportFromState(ctx, abstract.NetworkResource, tfstate, t, req.Name)
	if xerr != nil {
		return fail.Wrap(xerr, "failure exporting from terraform state")
	}

	return nil
}

func (t TfNetwork) Delete(ctx context.Context) fail.Error {
	// check there are no more hosts in the subnet
	tfhs, xerr := LoadTerraformHosts(ctx, t.svc)
	if xerr != nil {
		return xerr
	}

	count := 0
	for _, tfh := range tfhs {
		relic := tfh.(*TfHost) // nolint
		for _, nid := range relic.NetworkIDs {
			if nid == t.Identity {
				count = count + 1
			}
		}
	}

	if count > 1 {
		return fail.NewError("cannot delete network %s, there are still %d hosts in it", t.Name, count)
	}

	fname := t.Name
	if strings.HasPrefix(t.Name, "network-") {
		fname = strings.Split(t.Name, "-")[1]
	}

	tbr := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("%s-rendered.tf", fname))
	// if file does not exist, consider it done
	if _, err := os.Stat(tbr); err != nil {
		return fail.ConvertError(err)
	}
	err := os.Remove(tbr)
	if err != nil {
		return fail.ConvertError(err)
	}

	cleaner, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		defer func() {
			issue := cleaner()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return fail.ConvertError(err)
	}

	return nil
}

func (t TfNetwork) InspectSubnet(ctx context.Context, subnetRef string) (resources.Subnet, fail.Error) {
	return nil, fail.NewError("useless method")
}

func (t TfNetwork) ToProtocol(ctx context.Context) (*protocol.Network, fail.Error) {
	pn := &protocol.Network{
		Id:         t.Identity,
		Name:       t.Name,
		Cidr:       t.CIDR,
		Subnets:    []string{t.SubnetId},
		DnsServers: nil,
		Kvs:        toKvs(t.Tags),
	}

	return pn, nil
}
