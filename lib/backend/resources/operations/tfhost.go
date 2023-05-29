package operations

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sanity-io/litter"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func NewTerraformHost(svc iaas.Service) (*TfHost, fail.Error) {
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

	return &TfHost{
		svc:                         svc,
		terraformExecutableFullPath: tops.ExecutablePath,
		terraformWorkingDirectory:   tops.WorkPath,
	}, nil
}

type TfHost struct {
	ID           string            `json:"id,omitempty"`
	Name         string            `json:"name,omitempty"`
	PrivateKey   string            `json:"private_key,omitempty"`
	SSHPort      uint32            `json:"ssh_port,omitempty"`
	Password     string            `json:"password,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	PrivateIP    string            `json:"private_ip,omitempty"`
	PublicIP     string            `json:"public_ip,omitempty"`
	DiskSizeInGb int32             `json:"disk_size_in_gb,omitempty"`
	TemplateSize string            `json:"template_size,omitempty"`
	Operator     string            `json:"operator,omitempty"`

	InternalTerraformID string

	gw2SSHConfig *ssh.CommonConfig `json:"gw_2_ssh_config,omitempty"`
	gwSSHConfig  *ssh.CommonConfig `json:"gw_ssh_config,omitempty"`

	svc iaas.Service

	terraformExecutableFullPath string
	terraformWorkingDirectory   string

	Network    string   `json:"network,omitempty"`
	NetworkIDs []string `json:"networks,omitempty"`
	Nics       []string `json:"nics,omitempty"`
	SubnetID   string   `json:"subnet_id,omitempty"`

	VmIdentity string `json:"vm_identity,omitempty"`

	state hoststate.Enum
	// Create method initializes this, after that, we can safely work
	created *bool
}

func (t TfHost) IsNull() bool {
	if t.created == nil {
		return true
	}
	return false
}

func (t TfHost) Alter(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfHost) BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TfHost) Deserialize(ctx context.Context, buf []byte) fail.Error {
	return fail.NewError("useless method")
}

func (t TfHost) Inspect(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TfHost) Read(ctx context.Context, ref string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfHost) ReadByID(ctx context.Context, id string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfHost) Reload(ctx context.Context) fail.Error {
	return nil // useless method
}

func (t TfHost) Sdump(ctx context.Context) (string, fail.Error) {
	return litter.Sdump(t), nil
}

func (t TfHost) Service() iaas.Service {
	return t.svc
}

func (t TfHost) GetID() (string, error) {
	return t.ID, nil
}

func (t TfHost) GetName() string {
	return t.Name
}

func (t TfHost) ComplementFeatureParameters(ctx context.Context, v data.Map) fail.Error {
	return fail.NewError("useless method")
}

func (t TfHost) UnregisterFeature(ctx context.Context, feat string) fail.Error {
	return fail.NewError("useless method")
}

func (t TfHost) InstalledFeatures(ctx context.Context) ([]string, fail.Error) {
	return nil, fail.NewError("useless method")
}

func (t TfHost) InstallMethods(ctx context.Context) (map[uint8]installmethod.Enum, fail.Error) {
	return nil, fail.NewError("useless method")
}

func (t TfHost) RegisterFeature(ctx context.Context, feat resources.Feature, requiredBy resources.Feature, clusterContext bool) fail.Error {
	return fail.NewError("useless method")
}

func (t TfHost) TargetType() featuretargettype.Enum {
	return featuretargettype.Host
}

func (t TfHost) Exists(ctx context.Context) (bool, fail.Error) {
	return true, nil
}

func (t *TfHost) BindLabel(inctx context.Context, labelInstance resources.Label, value string) fail.Error {
	// join workDir with the module network name
	workDir := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("customcluster_%s", t.Network))

	type Extra struct {
		MachineName string
		Tags        map[string]string
	}
	ctf, xerr := t.svc.Render(inctx, abstract.HostResource, "customcluster", nil)
	if xerr != nil {
		return fail.ConvertError(fmt.Errorf("error rendering terraform files: %w", xerr))
	}
	sparks := t.Name
	if strings.HasPrefix(t.Name, "gw-") {
		sparks = "gw"
	}

	ctf[1].Name = fmt.Sprintf("machine-tags-%s.tf", sparks)

	newTags := t.Tags
	newTags[labelInstance.GetName()] = value

	ctf = []abstract.RenderedContent{ctf[1]}

	err := fsPersister(t.svc, t.terraformWorkingDirectory, workDir, ctf, Extra{MachineName: sparks, Tags: newTags})
	if err != nil {
		return fail.ConvertError(fmt.Errorf("error persisting terraform files: %w", err))
	}

	cleaner, ferr := applyTerraform(inctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if ferr != nil {
		defer func() {
			issue := cleaner()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return fail.Wrap(ferr, "failure applying terraform")
	}

	return nil
}

func (t TfHost) BindSecurityGroup(ctx context.Context, sg resources.SecurityGroup, enable resources.SecurityGroupActivation) fail.Error {
	return fail.NewError("not implemented for terraform driver, current securitygroup abstraction is invalid here")
}

func (t TfHost) Browse(ctx context.Context, callback func(*abstract.HostCore) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t *TfHost) Create(ctx context.Context, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements, extra interface{}) (*userdata.Content, fail.Error) {

	// List all the hosts in the state
	hosts, xerr := LoadTerraformHosts(ctx, t.svc)
	if xerr != nil {
		return nil, fail.ConvertError(fmt.Errorf("failed to list hosts: %w", xerr))
	}
	// make sure the host doesn't already exist
	for _, host := range hosts {
		if host.GetName() == hostReq.HostName {
			return nil, fail.DuplicateError("host already exists")
		}
	}

	err := renderTerraformHostFromFiles(ctx, t.svc, t.terraformWorkingDirectory, hostReq)
	if err != nil {
		return nil, fail.ConvertError(fmt.Errorf("failed to render terraform host: %w", err))
	}

	workPath := t.terraformWorkingDirectory

	// create a {cluster}-rendered.tf file
	err = prepareTerraformHostVars(ctx, t.svc, workPath, hostReq)
	if err != nil {
		return nil, fail.ConvertError(fmt.Errorf("failed to prepare terraform host vars: %w", err))
	}

	cleanup, err := createTerraformHost(ctx, t.svc, t.terraformExecutableFullPath, workPath, hostReq)
	if err != nil {
		cerr := cleanup()
		if cerr != nil {
			return nil, fail.NewErrorList([]error{err, cerr})
		}
		return nil, fail.ConvertError(fmt.Errorf("failed to create terraform host: %w", err))
	}

	// first, read terraform status
	tfstate, xerr := t.svc.GetTerraformState(ctx)
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = t.svc.ExportFromState(ctx, abstract.HostResource, tfstate, t, hostReq.HostName)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failure exporting from terraform state")
	}

	return nil, nil
}

func LoadTerraformHostObject(ctx context.Context, svc iaas.Service, hostName string) (*TfHost, error) {
	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(ctx)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failure getting terraform state")
	}

	tfh, xerr := NewTerraformHost(svc)
	if xerr != nil {
		return nil, xerr
	}

	thing, xerr := svc.ExportFromState(ctx, abstract.HostResource, tfstate, tfh, hostName)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failure loading from terraform state")
	}

	if answer, ok := thing.(*TfHost); ok {
		if answer != nil {
			return answer, nil
		}
	}

	return nil, fail.NotFoundError("host not found as a HostObject: %s", hostName)
}

func (t TfHost) Delete(ctx context.Context) fail.Error {
	// first, read terraform status
	tfstate, xerr := t.svc.GetTerraformState(ctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil
		default:
			return fail.Wrap(xerr, "failure getting terraform state")
		}
	}

	// If the host has attachments, drop it
	res, xerr := t.svc.ExportFromState(ctx, abstract.VolumeAttachmentResource, tfstate, nil, "")
	if xerr != nil {
		return fail.Wrap(xerr, "failure exporting from state")
	}

	pot, ok := res.([]*TfVolumeAttachment)
	if !ok {
		return fail.Wrap(xerr, "failure exporting from state")
	}

	for _, apot := range pot {
		if apot.AttachedHostId == t.ID {
			return fail.NewError("this machine is attached to disk %s", apot.AttachedDiskId)
		}
	}

	// which is my own network ?
	nn := t.Tags["NetworkName"]
	tn := t.Tags["Name"]

	// if exists terraform file, delete it
	terraFile := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("%s_%s", "customcluster", nn), fmt.Sprintf("machine-%s.tf", tn))

	// check terraFile exists with os.Stat
	_, err := os.Stat(terraFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return fail.ConvertError(err)
		}
		return nil
	}

	// delete terraFile
	err = os.Remove(terraFile)
	if err != nil {
		return fail.ConvertError(err)
	}

	// run 'terraform apply' to finish deletion
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

func (t TfHost) DisableSecurityGroup(ctx context.Context, sg resources.SecurityGroup) fail.Error {
	return fail.NewError("not implemented for terraform driver")
}

func (t TfHost) EnableSecurityGroup(ctx context.Context, sg resources.SecurityGroup) fail.Error {
	return fail.NewError("not implemented for terraform driver")
}

func (t TfHost) ForceGetState(ctx context.Context) (hoststate.Enum, fail.Error) {
	return hoststate.Started, nil
}

func (t TfHost) GetAccessIP(ctx context.Context) (string, fail.Error) {
	if t.PublicIP != "" {
		return t.PublicIP, nil
	}
	return t.PrivateIP, nil
}

func (t TfHost) GetDefaultSubnet(ctx context.Context) (resources.Subnet, fail.Error) {
	return nil, fail.NewError("not implemented for terraform driver")
}

func (t TfHost) GetMounts(ctx context.Context) (*propertiesv1.HostMounts, fail.Error) {
	return nil, fail.NewError("not implemented for terraform driver")
}

func (t TfHost) GetPrivateIP(ctx context.Context) (string, fail.Error) {
	return t.PrivateIP, nil
}

func (t TfHost) GetPrivateIPOnSubnet(ctx context.Context, subnetID string) (string, fail.Error) {
	return t.PrivateIP, nil
}

func (t TfHost) GetPublicIP(ctx context.Context) (string, fail.Error) {
	return t.PublicIP, nil
}

func (t TfHost) GetShare(ctx context.Context, shareRef string) (*propertiesv1.HostShare, fail.Error) {
	return nil, fail.NewError("not implemented for terraform driver")
}

func (t TfHost) GetShares(ctx context.Context) (*propertiesv1.HostShares, fail.Error) {
	return nil, fail.NewError("not implemented for terraform driver")
}

func (t TfHost) GetSSHConfig(ctx context.Context) (sshapi.Config, fail.Error) {
	aip, xerr := t.GetAccessIP(ctx)
	if xerr != nil {
		return nil, xerr
	}

	pip, xerr := t.GetPublicIP(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if pip == "" { // we need the gateway cfg...
		gw, err := LoadTerraformHostObject(ctx, t.svc, fmt.Sprintf("gw-%s", t.Network))
		if err != nil {
			return nil, fail.ConvertError(err)
		}
		theCfg, xerr := gw.GetSSHConfig(ctx)
		if xerr != nil {
			return nil, xerr
		}
		t.gwSSHConfig, xerr = ssh.NewConfigFrom(theCfg)
		if xerr != nil {
			return nil, xerr
		}
	}

	return ssh.NewConfig(t.Name, aip, 22, t.Operator, t.PrivateKey, 22, "", t.gwSSHConfig, t.gw2SSHConfig), nil
}

func (t TfHost) GetState(ctx context.Context) (hoststate.Enum, fail.Error) {
	return t.state, nil
}

func (t TfHost) GetVolumes(ctx context.Context) (*propertiesv1.HostVolumes, fail.Error) { // method never actually used, why is here ?
	return nil, fail.NewError("not implemented for terraform driver")
}

func (t TfHost) IsClusterMember(ctx context.Context) (bool, fail.Error) { // method never actually used, why is here ?
	return false, fail.NewError("not implemented for terraform driver")
}

func (t TfHost) IsFeatureInstalled(ctx context.Context, name string) (bool, fail.Error) {
	return false, fail.NewError("useless method")
}

func (t TfHost) IsGateway(ctx context.Context) (bool, fail.Error) {
	if v, ok := t.Tags["type"]; ok {
		if v == "gateway" {
			return true, nil
		}
		return false, nil
	}

	return false, fail.NewError("no type tag found")
}

func (t TfHost) IsSingle(ctx context.Context) (bool, fail.Error) {
	// get the type
	if v, ok := t.Tags["type"]; ok {
		switch v {
		case "gateway":
			return false, nil
		case "node":
			return false, nil
		case "master":
			return false, nil
		default:
			return true, nil
		}
	}

	return false, fail.NewError("no type tag found")
}

func (t TfHost) ListEligibleFeatures(ctx context.Context) ([]resources.Feature, fail.Error) {
	return nil, fail.NewError("useless method")
}

func (t TfHost) ListInstalledFeatures(ctx context.Context) ([]resources.Feature, fail.Error) {
	return nil, fail.NewError("useless method")
}

func (t TfHost) ListSecurityGroups(ctx context.Context, state securitygroupstate.Enum) ([]*propertiesv1.SecurityGroupBond, fail.Error) {
	return nil, fail.NewError("not implemented for terraform driver")
}

func (t TfHost) ListLabels(ctx context.Context) (list map[string]string, err fail.Error) {
	return t.Tags, nil
}

func (t TfHost) Pull(ctx context.Context, target, source string, timeout time.Duration) (int, string, string, fail.Error) {
	return -1, "", "", fail.NewError("not implemented for terraform driver")
}

func (t TfHost) Push(ctx context.Context, source, target, owner, mode string, timeout time.Duration) (int, string, string, fail.Error) {
	return -1, "", "", fail.NewError("not implemented for terraform driver")
}

func (t TfHost) PushStringToFileWithOwnership(ctx context.Context, content string, filename string, owner, mode string) fail.Error {
	return fail.NewError("not implemented for terraform driver")
}

func (t TfHost) Reboot(ctx context.Context, soft bool) fail.Error {
	return fail.NewError("not implemented for terraform driver")
}

func (t TfHost) ResetLabel(ctx context.Context, labelInstance resources.Label) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if labelInstance == nil {
		return fail.InvalidParameterCannotBeNilError("tag")
	}

	defaultValue, xerr := labelInstance.DefaultValue(ctx)
	if xerr != nil {
		return t.UpdateLabel(ctx, labelInstance, "")
	}

	return t.UpdateLabel(ctx, labelInstance, defaultValue)
}

func (t TfHost) Run(ctx context.Context, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (int, string, string, fail.Error) {
	return -1, "", "", fail.NewError("not implemented for terraform driver")
}

func (t TfHost) Start(ctx context.Context) fail.Error {
	return fail.NewError("not implemented for terraform driver")
}

func (t TfHost) Stop(ctx context.Context) fail.Error {
	return fail.NewError("not implemented for terraform driver")
}

func (t TfHost) ToProtocol(ctx context.Context) (*protocol.Host, fail.Error) {
	theId, err := t.GetID()
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	var theTl *abstract.HostTemplate
	if t.TemplateSize != "" {
		atl, err := t.svc.ListTemplates(ctx, false)
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		for _, at := range atl {
			if at.Name == t.TemplateSize {
				theTl = at
				break
			}
		}
	}

	var gvID string
	if t.Network != "" {
		if gw, xerr := LoadTerraformHostObject(ctx, t.svc, fmt.Sprintf("gw-%s", t.Network)); xerr != nil {
			gvID = gw.ID
		}
	}

	// FIXME: Populate the rest of the fields
	return &protocol.Host{
		Id:                  theId,
		Name:                t.GetName(),
		Cpu:                 int32(theTl.Cores),
		Ram:                 theTl.RAMSize,
		Disk:                t.DiskSizeInGb,
		PublicIp:            t.PublicIP,
		PrivateIp:           t.PrivateIP,
		State:               protocol.HostState(2), // started
		PrivateKey:          t.PrivateKey,
		GatewayId:           gvID,
		OsKind:              "",
		AttachedVolumeNames: nil,
		Password:            t.Password,
		SshPort:             int32(t.SSHPort),
		StateLabel:          "",
		CreationDate:        t.Tags["CreationDate"],
		Managed:             isManaged(t),
		Template:            t.TemplateSize,
		Labels:              toLabels(t.Tags),
		Kvs:                 toKvs(t.Tags),
	}, nil
}

func isManaged(t TfHost) bool {
	if v, ok := t.Tags["managedBy"]; ok {
		if v == "safescale" {
			return true
		}
		return false
	}

	return false
}

func toLabels(tags map[string]string) []*protocol.HostLabelResponse {
	var labels []*protocol.HostLabelResponse
	for k, v := range tags {
		labels = append(labels, &protocol.HostLabelResponse{
			Name:       k,
			HasDefault: true,
			Value:      v,
		})
	}
	return labels
}

func toKvs(tags map[string]string) []*protocol.KeyValue {
	var kvs []*protocol.KeyValue
	for k, v := range tags {
		kvs = append(kvs, &protocol.KeyValue{Key: k, Value: v})
	}
	return kvs
}

func (t TfHost) UnbindSecurityGroup(ctx context.Context, sg resources.SecurityGroup) fail.Error {
	return fail.NewError("not implemented for terraform driver")
}

func (t *TfHost) UnbindLabel(inctx context.Context, labelInstance resources.Label) fail.Error {
	// join workDir with the module network name
	workDir := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("customcluster_%s", t.Network))

	type Extra struct {
		MachineName string
		Tags        map[string]string
	}
	ctf, xerr := t.svc.Render(inctx, abstract.HostResource, "customcluster", nil)
	if xerr != nil {
		return fail.ConvertError(fmt.Errorf("error rendering terraform files: %w", xerr))
	}

	sparks := t.Name
	if strings.HasPrefix(t.Name, "gw-") {
		sparks = "gw"
	}

	ctf[1].Name = fmt.Sprintf("machine-tags-%s.tf", sparks)

	delete(t.Tags, labelInstance.GetName())
	newTags := t.Tags

	ctf = []abstract.RenderedContent{ctf[1]}

	err := fsPersister(t.svc, t.terraformWorkingDirectory, workDir, ctf, Extra{MachineName: sparks, Tags: newTags})
	if err != nil {
		return fail.ConvertError(fmt.Errorf("error persisting terraform files: %w", err))
	}

	cleaner, ferr := applyTerraform(inctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if ferr != nil {
		defer func() {
			issue := cleaner()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return fail.Wrap(ferr, "failure applying terraform")
	}

	return nil
}

func (t *TfHost) UpdateLabel(inctx context.Context, labelInstance resources.Label, value string) fail.Error {
	return t.BindLabel(inctx, labelInstance, value)
}

func (t TfHost) WaitSSHReady(ctx context.Context, timeout time.Duration) (status string, err fail.Error) {
	return "", fail.NewError("not implemented for terraform driver")
}
