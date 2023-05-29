package operations

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	uuidpkg "github.com/gofrs/uuid"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/sanity-io/litter"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type TerraformCluster struct {
	svc                         iaas.Service
	terraformExecutableFullPath string
	terraformWorkingDirectory   string

	Name       string
	Identity   string
	Complexity clustercomplexity.Enum
	Flavor     clusterflavor.Enum
}

func NewTerraformCluster(svc iaas.Service) (*TerraformCluster, fail.Error) {
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

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	return &TerraformCluster{svc: svc, terraformExecutableFullPath: tops.ExecutablePath, terraformWorkingDirectory: tops.WorkPath, Identity: uuid.String(), Flavor: clusterflavor.BOH}, nil
}

func (t TerraformCluster) IsNull() bool {
	return valid.IsNil(t)
}

func (t TerraformCluster) Alter(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TerraformCluster) BrowseFolder(ctx context.Context, callback func(buf []byte) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TerraformCluster) Deserialize(ctx context.Context, buf []byte) fail.Error {
	return fail.NewError("useless method")
}

func (t TerraformCluster) Inspect(ctx context.Context, callback resources.Callback) fail.Error {
	return fail.NewError("useless method")
}

func (t TerraformCluster) Read(ctx context.Context, ref string) fail.Error {
	return fail.NewError("useless method")
}

func (t TerraformCluster) ReadByID(ctx context.Context, id string) fail.Error {
	return fail.NewError("useless method")
}

func (t TerraformCluster) Reload(ctx context.Context) fail.Error {
	return fail.NewError("useless method")
}

func (t TerraformCluster) Sdump(ctx context.Context) (string, fail.Error) {
	return litter.Sdump(t), nil
}

func (t TerraformCluster) Service() iaas.Service {
	return t.svc
}

func (t TerraformCluster) GetID() (string, error) {
	return t.Identity, nil
}

func (t TerraformCluster) GetName() string {
	return t.Name
}

func (t TerraformCluster) ComplementFeatureParameters(ctx context.Context, v data.Map) fail.Error {
	return fail.NewError("useless method") // feature related
}

func (t TerraformCluster) UnregisterFeature(ctx context.Context, feat string) fail.Error {
	return fail.NewError("useless method") // feature related
}

func (t TerraformCluster) InstalledFeatures(ctx context.Context) ([]string, fail.Error) {
	return nil, fail.NewError("useless method") // feature related
}

func (t TerraformCluster) InstallMethods(ctx context.Context) (map[uint8]installmethod.Enum, fail.Error) {
	return nil, fail.NewError("useless method") // feature related
}

func (t TerraformCluster) RegisterFeature(ctx context.Context, feat resources.Feature, requiredBy resources.Feature, clusterContext bool) fail.Error {
	return fail.NewError("useless method") // feature related
}

func (t TerraformCluster) TargetType() featuretargettype.Enum {
	return featuretargettype.Cluster
}

func (t TerraformCluster) Exists(ctx context.Context) (bool, fail.Error) {
	return true, nil
}

func (t TerraformCluster) AddFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	return nil, fail.NewError("useless method") // feature related
}

func readFileBody(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (t TerraformCluster) AddNodes(ctx context.Context, name string, count uint, def abstract.HostSizingRequirements, parameters data.Map, keepOnFailure bool) ([]resources.Host, fail.Error) {
	var names []string

	// List the nodes...
	hosts, xerr := LoadTerraformHosts(ctx, t.svc)
	if xerr != nil {
		return nil, xerr
	}

	for _, host := range hosts {
		if strings.Contains(host.GetName(), fmt.Sprintf("%s-node-", t.Name)) {
			names = append(names, host.GetName())
		}
	}
	sort.Strings(names)

	// Delete the last one...
	lastName := names[len(names)-1]
	frag := strings.Split(lastName, "-")
	num, err := strconv.Atoi(frag[len(frag)-1])
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	for i := num + 1; i <= int(num+int(count)+1); i++ {
		err := renderTerraformHostFromFiles(ctx, t.svc, t.terraformWorkingDirectory, abstract.HostRequest{
			HostName:    fmt.Sprintf("%s-node-%d", t.Name, i),
			SubnetNames: []string{t.Name},
		})
		if err != nil {
			return nil, fail.ConvertError(fmt.Errorf("failed to render terraform host: %w", err))
		}
	}

	// run terraform apply
	cleanup, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		defer func() {
			issue := cleanup()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return nil, fail.Wrap(err, "error updating cluster")
	}

	// return no errors
	return nil, nil
}

func (t TerraformCluster) Browse(ctx context.Context, callback func(*abstract.ClusterIdentity) fail.Error) fail.Error {
	return fail.NewError("useless method")
}

func (t TerraformCluster) CheckFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	return nil, fail.NewError("useless method") // feature related
}

func (t *TerraformCluster) alternativeCreate(ctx context.Context, req abstract.ClusterRequest) fail.Error {
	t.Name = req.Name

	err := renderTerraformCustomClusterFromFiles(ctx, t.svc, t.terraformWorkingDirectory, req)
	if err != nil {
		return fail.ConvertError(err)
	}

	// create a {cluster}-rendered.tf file
	err = prepareCustomClusterTerraformVars(ctx, t.svc, t.terraformWorkingDirectory, req)
	if err != nil {
		return fail.ConvertError(err)
	}

	cleaner, err := createTerraformCluster(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory, req)
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

func (t *TerraformCluster) Create(ctx context.Context, req abstract.ClusterRequest) fail.Error {
	t.Flavor = req.Flavor
	t.Complexity = req.Complexity

	return t.alternativeCreate(ctx, req)
}

func diskSizeChooser(a int, b int) uint {
	c := max(a, b)
	if c > 0 {
		return c
	}
	return 60
}

func max(a int, b int) uint {
	if a > b {
		return uint(a)
	}
	return uint(b)
}

func (t TerraformCluster) DeleteSpecificNode(ctx context.Context, hostID string, selectedMasterID string) fail.Error {
	// List the nodes...
	ct, xerr := t.listMachines(ctx)
	if xerr != nil {
		return xerr
	}

	hosts := ct["nodes"]

	var target *TfHost
	for _, host := range hosts {
		theID, err := host.GetID()
		if err != nil {
			continue
		}
		if theID == hostID {
			target = host
		}

		if hostID == host.GetName() {
			target = host
		}
	}
	if target == nil {
		return fail.NotFoundError("node %s not found", hostID)
	}

	lastName := target.Name

	// get the path to the terraform file
	machineName := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("customcluster_%s", t.Name), fmt.Sprintf("machine-%s.tf", lastName))
	err := os.Remove(machineName)
	if err != nil {
		if !os.IsNotExist(err) {
			return fail.ConvertError(err)
		}
	}

	tagMachineName := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("customcluster_%s", t.Name), fmt.Sprintf("machine-tags-%s.tf", lastName))
	err = os.Remove(tagMachineName)
	if err != nil {
		if !os.IsNotExist(err) {
			return fail.ConvertError(err)
		}
	}

	// run terraform apply
	cleanup, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		defer func() {
			issue := cleanup()
			if issue != nil {
				logrus.Debugf("error cleaning up: %v", issue)
			}
		}()
		return fail.Wrap(err, "error updating cluster")
	}

	// return no errors
	return nil
}

func (t TerraformCluster) verifyThereAreNoAttachments(ctx context.Context) error {
	var machineIds []string
	// list all cluster machines
	lma, xerr := t.listMachines(ctx)
	if xerr != nil {
		return xerr
	}
	for _, v := range lma["gateways"] {
		machineIds = append(machineIds, v.ID)
	}
	for _, v := range lma["masters"] {
		machineIds = append(machineIds, v.ID)
	}
	for _, v := range lma["nodes"] {
		machineIds = append(machineIds, v.ID)
	}

	// list all attachments
	tfstate, xerr := t.svc.GetTerraformState(ctx)
	if xerr != nil {
		return xerr
	}

	empty := &TfVolumeAttachment{}
	tats, xerr := t.svc.ExportFromState(ctx, abstract.VolumeAttachmentResource, tfstate, empty, "")
	if xerr != nil {
		return fail.Wrap(xerr, "failure exporting from terraform state")
	}
	atts := tats.([]*TfVolumeAttachment)

	// if the attached host id of one attachment is in a cluster machine, bail
	for _, v := range atts {
		for _, id := range machineIds {
			if v.AttachedHostId == id {
				return fail.InvalidRequestError("cluster %s has volumes attached, please detach them before deleting the cluster", t.Name)
			}
		}
	}

	return nil
}

// Delete deletes the cluster and its resources and also the infrastructure created with terraform
func (t TerraformCluster) Delete(ctx context.Context, force bool) fail.Error {
	err := t.verifyThereAreNoAttachments(ctx)
	if err != nil {
		return fail.ConvertError(err)
	}

	tbr := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("%s-rendered.tf", t.Name))
	// if file does not exist, consider it done
	if _, err := os.Stat(tbr); err != nil {
		return fail.ConvertError(err)
	}
	err = os.Remove(tbr)
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

	// Also delete the source files
	files, err := filepath.Glob(filepath.Join(filepath.Join(t.terraformWorkingDirectory, "customcluster"), fmt.Sprintf("%s-*", t.Name)))
	if err != nil {
		return fail.ConvertError(err)
	}
	for _, file := range files {
		err = os.RemoveAll(file)
		if err != nil {
			return fail.ConvertError(err)
		}
	}

	return nil
}

func adaptTerraformInfrastructure(inctx context.Context, execPath string, workPath string, top *tfexec.TargetOption) error {
	_ = os.MkdirAll(workPath, 0777)

	workingDir, err := filepath.Abs(workPath)
	if err != nil {
		return fmt.Errorf("error running NewTerraform: %w", err)
	}

	_, err = os.Stat(workPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		err = os.Mkdir(workPath, 0750)
		if err != nil {
			return err
		}
	}

	tf, err := tfexec.NewTerraform(workingDir, execPath)
	if err != nil {
		return fmt.Errorf("error running NewTerraform: %w", err)
	}

	err = tf.Init(inctx, tfexec.Upgrade(false))
	if err != nil {
		return fmt.Errorf("error running Init: %w", err)
	}

	err = tf.Destroy(inctx, top)
	if err != nil {
		return err
	}

	// get terraform state
	backup, err := tf.StatePull(inctx)
	if err != nil {
		return fmt.Errorf("error running StatePull: %w", err)
	}

	// write terraform state to file
	err = os.WriteFile(filepath.Join(workingDir, "tfstate.backup"), []byte(backup), 0644)
	if err != nil {
		return err
	}

	return nil
}

func (t TerraformCluster) FindAvailableMaster(ctx context.Context) (resources.Host, fail.Error) {
	return nil, fail.NewError("not implemented for terraform driver") // feature related
}

func (t TerraformCluster) GetIdentity(ctx context.Context) (abstract.ClusterIdentity, fail.Error) {
	return abstract.ClusterIdentity{}, fail.NewError("never actually used")
}

func (t TerraformCluster) GetFlavor(ctx context.Context) (clusterflavor.Enum, fail.Error) {
	return clusterflavor.BOH, nil
}

func (t TerraformCluster) GetComplexity(ctx context.Context) (clustercomplexity.Enum, fail.Error) {
	return t.Complexity, nil
}

func (t TerraformCluster) GetAdminPassword(ctx context.Context) (string, fail.Error) {
	return "", fail.NewError("never actually used")
}

func (t TerraformCluster) GetKeyPair(ctx context.Context) (*abstract.KeyPair, fail.Error) {
	return nil, fail.NewError("never actually used")
}

func (t TerraformCluster) GetNetworkConfig(ctx context.Context) (*propertiesv3.ClusterNetwork, fail.Error) {
	return nil, fail.NewError("never actually used")
}

func (t TerraformCluster) GetState(ctx context.Context) (clusterstate.Enum, fail.Error) {
	return clusterstate.Unknown, fail.NewError("not implemented for terraform driver") // does not make sense
}

func (t TerraformCluster) IsFeatureInstalled(ctx context.Context, name string) (found bool, ferr fail.Error) {
	return false, fail.NewError("not implemented for terraform driver") // feature related
}

func (t TerraformCluster) ListEligibleFeatures(ctx context.Context) ([]resources.Feature, fail.Error) {
	return nil, fail.NewError("not implemented for terraform driver") // feature related
}

func (t TerraformCluster) ListInstalledFeatures(ctx context.Context) ([]resources.Feature, fail.Error) {
	return nil, fail.NewError("not implemented for terraform driver") // feature related
}

func (t TerraformCluster) ListMasters(ctx context.Context) (resources.IndexedListOfClusterNodes, fail.Error) {
	hosts, xerr := LoadTerraformHosts(ctx, t.svc)
	if xerr != nil {
		return nil, xerr
	}
	answer := make(resources.IndexedListOfClusterNodes)
	for ind, host := range hosts {
		aho := host.(*TfHost)
		if !strings.Contains(aho.Name, fmt.Sprintf("%s-master-", t.Name)) {
			continue
		}
		if !strings.Contains(aho.Network, t.Name) {
			continue
		}
		answer[uint(ind)] = &propertiesv3.ClusterNode{
			ID:          aho.ID,
			NumericalID: uint(ind),
			Name:        aho.Name,
			PublicIP:    aho.PublicIP,
			PrivateIP:   aho.PrivateIP,
		}
	}

	return answer, nil
}

func (t TerraformCluster) listMachines(ctx context.Context) (map[string][]*TfHost, fail.Error) {
	hosts, xerr := LoadTerraformHosts(ctx, t.svc)
	if xerr != nil {
		return nil, xerr
	}

	answer := make(map[string][]*TfHost)
	var gws []*TfHost
	var masters []*TfHost
	var nodes []*TfHost

	var first *TfHost
	var second *TfHost

	for _, host := range hosts {
		aho := host.(*TfHost)
		if aho.Name == fmt.Sprintf("gw-%s", t.Name) {
			first = aho
		}
		if aho.Name == fmt.Sprintf("gw2-%s", t.Name) {
			second = aho
		}
		if strings.Contains(aho.Name, fmt.Sprintf("%s-master-", t.Name)) {
			masters = append(masters, aho)
		}
		if strings.Contains(aho.Name, fmt.Sprintf("%s-node-", t.Name)) {
			nodes = append(nodes, aho)
		}
	}

	if first != nil {
		gws = append(gws, first)
	}
	if second != nil {
		gws = append(gws, second)
	}

	answer["masters"] = masters
	answer["nodes"] = nodes
	answer["gateways"] = gws

	return answer, nil
}

func (t TerraformCluster) ListNodes(ctx context.Context) (resources.IndexedListOfClusterNodes, fail.Error) {
	hosts, xerr := LoadTerraformHosts(ctx, t.svc)
	if xerr != nil {
		return nil, xerr
	}
	answer := make(resources.IndexedListOfClusterNodes)
	for ind, host := range hosts {
		aho := host.(*TfHost)
		if !strings.Contains(aho.Name, fmt.Sprintf("%s-node-", t.Name)) {
			continue
		}
		if !strings.Contains(aho.Network, t.Name) {
			continue
		}
		answer[uint(ind)] = &propertiesv3.ClusterNode{
			ID:          aho.ID,
			NumericalID: uint(ind),
			Name:        aho.Name,
			PublicIP:    aho.PublicIP,
			PrivateIP:   aho.PrivateIP,
		}
	}

	return answer, nil
}

func (t TerraformCluster) RemoveFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	return nil, fail.NewError("not implemented for terraform driver") // feature related
}

func (t TerraformCluster) Shrink(ctx context.Context, name string, count uint) ([]*propertiesv3.ClusterNode, fail.Error) {
	var names []string

	// List the nodes...
	hosts, xerr := LoadTerraformHosts(ctx, t.svc)
	if xerr != nil {
		return nil, xerr
	}

	for _, host := range hosts {
		if strings.Contains(host.GetName(), fmt.Sprintf("%s-node-", t.Name)) {
			names = append(names, host.GetName())
		}
	}
	sort.Strings(names)

	for i := 1; i < int(count); i++ {
		if len(names) < i {
			break
		}

		// Delete the last one...
		lastName := names[len(names)-i]

		// get the path to the terraform file
		machineName := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("customcluster_%s", t.Name), fmt.Sprintf("machine-%s.tf", lastName))
		err := os.Remove(machineName)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fail.ConvertError(err)
			}
		}

		tagMachineName := filepath.Join(t.terraformWorkingDirectory, fmt.Sprintf("customcluster_%s", t.Name), fmt.Sprintf("machine-tags-%s.tf", lastName))
		err = os.Remove(tagMachineName)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fail.ConvertError(err)
			}
		}
	}

	// run terraform apply
	cleanup, err := applyTerraform(ctx, t.svc, t.terraformExecutableFullPath, t.terraformWorkingDirectory)
	if err != nil {
		defer func() {
			_ = cleanup()
		}()
		return nil, fail.Wrap(err, "error updating cluster")
	}

	// return no errors
	return nil, nil
}

func (t TerraformCluster) Start(ctx context.Context) fail.Error {
	return fail.NewError("not implemented for terraform driver")
}

func (t TerraformCluster) Stop(ctx context.Context) fail.Error {
	return fail.NewError("not implemented for terraform driver")
}

func (t TerraformCluster) ToProtocol(ctx context.Context) (*protocol.ClusterResponse, fail.Error) {
	var masters []*protocol.Host
	var nodes []*protocol.Host
	var cidr string
	var networkID string
	var subnetworkID string
	var clusterPublicIP string
	var clusterPrivateKey string

	if t.Name == "" {
		return nil, fail.InvalidInstanceError()
	}

	machineMap, xerr := t.listMachines(ctx)
	if xerr != nil {
		return nil, xerr
	}

	tfnet, xerr := LoadTerraformNetwork(ctx, t.svc, t.Name)
	if xerr != nil {
		return nil, xerr
	}

	cidr = tfnet.CIDR

	clusterPublicIP = machineMap["gateways"][0].PublicIP
	gwPass := machineMap["gateways"][0].Password
	gwID := machineMap["gateways"][0].ID
	gwInternalIP := machineMap["gateways"][0].PrivateIP
	subnetworkID = machineMap["gateways"][0].SubnetID
	networkID = machineMap["gateways"][0].NetworkIDs[0]

	for _, host := range machineMap["masters"] {
		masters = append(masters, &protocol.Host{
			Id:        host.ID,
			Name:      host.Name,
			PublicIp:  host.PublicIP,
			PrivateIp: host.PrivateIP,
		})
	}

	for _, host := range machineMap["nodes"] {
		nodes = append(nodes, &protocol.Host{
			Id:        host.ID,
			Name:      host.Name,
			PublicIp:  host.PublicIP,
			PrivateIp: host.PrivateIP,
		})
	}

	return &protocol.ClusterResponse{
		Identity: &protocol.ClusterIdentity{
			Name:          t.Name,
			Complexity:    protocol.ClusterComplexity(t.Complexity),
			Flavor:        protocol.ClusterFlavor(clusterflavor.BOH),
			AdminPassword: gwPass,
			PrivateKey:    clusterPrivateKey,
		},
		Network: &protocol.ClusterNetwork{
			NetworkId:          networkID,
			Cidr:               cidr,
			Domain:             "",
			GatewayId:          gwID,
			GatewayIp:          clusterPublicIP,
			SecondaryGatewayId: "",
			SecondaryGatewayIp: "",
			DefaultRouteIp:     gwInternalIP,
			PrimaryPublicIp:    clusterPublicIP,
			SecondaryPublicIp:  "",
			EndpointIp:         clusterPublicIP,
			SubnetId:           subnetworkID,
		},
		Masters:           masters,
		Nodes:             nodes,
		DisabledFeatures:  &protocol.FeatureListResponse{},
		InstalledFeatures: &protocol.FeatureListResponse{},
		State:             protocol.ClusterState(clusterstate.Nominal),
		Composite:         &protocol.ClusterComposite{},
		Controlplane:      &protocol.ClusterControlplane{},
	}, nil
}
