package operations

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sanity-io/litter"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strings"
)

func NewTerraformSubnet(svc iaas.Service) (*TfSubnet, fail.Error) {
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

	return &TfSubnet{svc: svc, terraformExecutableFullPath: tops.ExecutablePath, terraformWorkingDirectory: tops.WorkPath, Tags: make(map[string]string)}, nil
}

func ListTerraformSubnets(inctx context.Context, svc iaas.Service, networkRef, sunetRef string, all bool) ([]*TfSubnet, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(inctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return []*TfSubnet{}, nil
		default:
			return nil, xerr
		}
	}

	var results []*TfSubnet

	// recover the subnet information
	maybe, xerr := svc.ExportFromState(inctx, abstract.SubnetResource, tfstate, &TfSubnet{}, "")
	if xerr != nil {
		logrus.WithContext(inctx).Warnf("failure exporting from state: %v", xerr)
		return nil, xerr
	}

	results = maybe.([]*TfSubnet)
	for _, res := range results {
		res.svc = svc
	}

	return results, nil
}

func LoadTerraformSubnet(inctx context.Context, svc iaas.Service, networkRef, sunetRef string) (*TfSubnet, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	subnets, err := ListTerraformSubnets(inctx, svc, networkRef, sunetRef, false)
	if err != nil {
		return nil, err
	}

	for _, subnet := range subnets {
		if subnet.Name == sunetRef || strings.Contains(subnet.Name, sunetRef) {
			if subnet.NetworkName == networkRef || strings.Contains(subnet.NetworkName, networkRef) {
				return subnet, nil
			}
		}
	}

	return nil, fail.NotFoundError("subnet %s not found", sunetRef)
}

type TfSubnet struct {
	svc                         iaas.Service
	terraformExecutableFullPath string
	terraformWorkingDirectory   string

	Name        string
	Identity    string
	NetworkName string
	NetworkID   string
	GatewayIDS  []string
	CIDR        string
	Tags        map[string]string
}

func (t TfSubnet) IsNull() bool {
	return false
}

func (t TfSubnet) Alter(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) Deserialize(ctx context.Context, buf []byte) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) Inspect(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) Read(ctx context.Context, ref string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) ReadByID(ctx context.Context, id string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) Reload(ctx context.Context) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) Sdump(ctx context.Context) (string, fail.Error) {
	return litter.Sdump(t), nil
}

func (t TfSubnet) Service() iaas.Service {
	return t.svc
}

func (t TfSubnet) GetID() (string, error) {
	return t.Identity, nil
}

func (t TfSubnet) Exists(ctx context.Context) (bool, fail.Error) {
	return true, nil
}

func (t TfSubnet) GetName() string {
	return t.Name
}

func (t TfSubnet) DetachHost(ctx context.Context, hostID string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) AttachHost(ctx context.Context, host resources.Host) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) BindSecurityGroup(ctx context.Context, group resources.SecurityGroup, activation resources.SecurityGroupActivation) fail.Error {
	return fail.NewError("useless method, does not make sense") // security group cannot be "unbound", it does not exist outside a network
}

func (t TfSubnet) Browse(ctx context.Context, callback func(*abstract.Subnet) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t *TfSubnet) Create(ctx context.Context, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements, extra interface{}) fail.Error {
	cfg, xerr := t.svc.GetConfigurationOptions(ctx)
	if xerr != nil {
		return fail.Wrap(xerr, "error recovering cfg")
	}

	err := renderTerraformSubNetworkFromFiles(ctx, t.svc, t.terraformWorkingDirectory, req)
	if err != nil {
		return fail.ConvertError(err)
	}

	workPath := t.terraformWorkingDirectory

	if req.ImageRef == "" {
		req.ImageRef = cfg.GetString("DefaultImage")
	}

	// create a {cluster}-rendered.tf file
	err = prepareTerraformSubNetworkVars(ctx, t.svc, workPath, req)
	if err != nil {
		return fail.ConvertError(err)
	}

	cleanup, err := createTerraformSubNetwork(ctx, t.svc, t.terraformExecutableFullPath, workPath, req)
	if err != nil {
		cerr := cleanup()
		if cerr != nil {
			return fail.NewErrorList([]error{err, cerr})
		}
		return fail.ConvertError(err)
	}

	// first, read terraform status
	tfstate, xerr := t.svc.GetTerraformState(ctx)
	if xerr != nil {
		return xerr
	}

	_, xerr = t.svc.ExportFromState(ctx, abstract.SubnetResource, tfstate, t, req.Name)
	if xerr != nil {
		return fail.Wrap(xerr, "failure exporting from terraform state")
	}

	return nil
}

func (t TfSubnet) Delete(ctx context.Context) fail.Error {
	// check there are no more hosts in the subnet

	tfhs, xerr := LoadTerraformHosts(ctx, t.svc)
	if xerr != nil {
		return xerr
	}

	count := 0
	for _, tfh := range tfhs {
		relic := tfh.(*TfHost)
		if relic.SubnetID == t.Identity {
			count = count + 1
		}
	}

	if count > 1 {
		return fail.NewError("cannot delete subnet %s, there are still %d hosts other than the gw in it", t.Name, count-1)
	}

	fname := t.Name
	if strings.HasPrefix(t.Name, "subnet-") {
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

func (t TfSubnet) DisableSecurityGroup(ctx context.Context, group resources.SecurityGroup) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) EnableSecurityGroup(ctx context.Context, group resources.SecurityGroup) fail.Error {
	return fail.NewError("useless method")
}

func (t TfSubnet) GetGatewayPublicIP(ctx context.Context, primary bool) (string, fail.Error) {
	return "", fail.NewError("never actually used")
}

func (t TfSubnet) GetGatewayPublicIPs(ctx context.Context) ([]string, fail.Error) {
	return nil, fail.NewError("never actually used")
}

func (t TfSubnet) GetDefaultRouteIP(ctx context.Context) (string, fail.Error) {
	return "", fail.NewError("never actually used")
}

func (t TfSubnet) GetEndpointIP(ctx context.Context) (string, fail.Error) {
	return "", fail.NewError("useless method") // features related
}

func (t TfSubnet) GetCIDR(ctx context.Context) (string, fail.Error) {
	return t.CIDR, nil
}

func (t TfSubnet) GetState(ctx context.Context) (subnetstate.Enum, fail.Error) {
	return subnetstate.Unknown, fail.NewError("never actually used")
}

func (t TfSubnet) HasVirtualIP(ctx context.Context) (bool, fail.Error) {
	return false, nil
}

func (t TfSubnet) InspectGateway(ctx context.Context, primary bool) (resources.Host, fail.Error) {
	if primary {
		atf, err := LoadTerraformHostObject(ctx, t.svc, fmt.Sprintf("gw-%s", t.NetworkName))
		if err != nil {
			return nil, fail.ConvertError(err)
		}
		return atf, nil
	}

	atf2, err := LoadTerraformHostObject(ctx, t.svc, fmt.Sprintf("gw2-%s", t.NetworkName))
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return atf2, nil
}

func (t TfSubnet) InspectGatewaySecurityGroup(ctx context.Context) (resources.SecurityGroup, fail.Error) {
	return nil, fail.NewError("useless method") // features related
}

func (t TfSubnet) InspectInternalSecurityGroup(ctx context.Context) (resources.SecurityGroup, fail.Error) {
	return nil, fail.NewError("useless method") // unused
}

func (t TfSubnet) InspectPublicIPSecurityGroup(ctx context.Context) (resources.SecurityGroup, fail.Error) {
	return nil, fail.NewError("useless method") // unused
}

func (t TfSubnet) InspectNetwork(ctx context.Context) (resources.Network, fail.Error) {
	return nil, fail.NewError("useless method") // unused
}

func (t TfSubnet) ListHosts(ctx context.Context) ([]resources.Host, fail.Error) {
	return nil, fail.NewError("useless method")
}

func (t TfSubnet) ListSecurityGroups(ctx context.Context, state securitygroupstate.Enum) ([]*propertiesv1.SecurityGroupBond, fail.Error) {
	sgs, xerr := ListTerraformSGs(ctx, t.svc)
	if xerr != nil {
		return nil, xerr
	}

	var res []*propertiesv1.SecurityGroupBond
	for _, sg := range sgs {
		res = append(res, &propertiesv1.SecurityGroupBond{
			Name: sg.Name,
			ID:   sg.Identity,
		})
	}

	return res, nil
}

func (t TfSubnet) ToProtocol(ctx context.Context) (*protocol.Subnet, fail.Error) {
	return &protocol.Subnet{
		Id:         t.Identity,
		Name:       t.Name,
		Cidr:       t.CIDR,
		GatewayIds: t.GatewayIDS,
		VirtualIp:  nil,
		Failover:   false,
		State:      0,
		NetworkId:  t.NetworkID,
		Kvs:        toKvs(t.Tags),
	}, nil
}

func (t TfSubnet) UnbindSecurityGroup(ctx context.Context, group resources.SecurityGroup) fail.Error {
	return fail.NewError("useless method, does not make sense") // security group cannot be "unbound", it does not exist outside a network
}
