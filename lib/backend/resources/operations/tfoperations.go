package operations

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	uuidpkg "github.com/gofrs/uuid"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/sirupsen/logrus"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	_ "github.com/hashicorp/hcl/v2"
	_ "github.com/hashicorp/hcl/v2/hclwrite"
	_ "github.com/zclconf/go-cty/cty"
)

type NetworkCreationParameters struct {
	Name           string `json:"Name"`
	Identity       string `json:"Identity"`
	CreationDate   string `json:"CreationDate"`
	Cidr           string `json:"Cidr"`
	Masters        uint   `json:"Masters"`
	DefaultGateway string `json:"DefaultGateway"`
	Region         string `json:"Region"`
	GwTemplate     string `json:"GwTemplate"`
	MasterTemplate string `json:"MasterTemplate"`

	GwDiskSize     uint `json:"GwDiskSize"`
	MasterDiskSize uint `json:"MasterDiskSize"`

	GwOsPublisher string `json:"GwOsPublisher"`
	GwOsOffer     string `json:"GwOsOffer"`
	GwOsSku       string `json:"GwOsSku"`
	GwOsVersion   string `json:"GwOsVersion"`

	MasterOsPublisher string `json:"MasterOsPublisher"`
	MasterOsOffer     string `json:"MasterOsOffer"`
	MasterOsSku       string `json:"MasterOsSku"`
	MasterOsVersion   string `json:"MasterOsVersion"`
	OperatorUsername  string `json:"OperatorUsername"`
}

type SubnetCreationParameters struct {
	Name             string `json:"Name"`
	Identity         string `json:"Identity"`
	Cidr             string `json:"Cidr"`
	Nodes            uint   `json:"Nodes"`
	Masters          uint   `json:"Masters"`
	DefaultGateway   string `json:"DefaultGateway"`
	OperatorUsername string `json:"OperatorUsername"`
	GwTemplate       string `json:"GwTemplate"`
	NodeTemplate     string `json:"NodeTemplate"`
	MasterTemplate   string `json:"MasterTemplate"`

	CreationDate string `json:"CreationDate"`

	GwDiskSize     uint `json:"GwDiskSize"`
	NodeDiskSize   uint `json:"NodeDiskSize"`
	MasterDiskSize uint `json:"MasterDiskSize"`

	GwOsPublisher string `json:"GwOsPublisher"`
	GwOsOffer     string `json:"GwOsOffer"`
	GwOsSku       string `json:"GwOsSku"`
	GwOsVersion   string `json:"GwOsVersion"`

	NodeOsPublisher string `json:"NodeOsPublisher"`
	NodeOsOffer     string `json:"NodeOsOffer"`
	NodeOsSku       string `json:"NodeOsSku"`
	NodeOsVersion   string `json:"NodeOsVersion"`

	MasterOsPublisher string `json:"MasterOsPublisher"`
	MasterOsOffer     string `json:"MasterOsOffer"`
	MasterOsSku       string `json:"MasterOsSku"`
	MasterOsVersion   string `json:"MasterOsVersion"`
	Region            string `json:"Region"`
}

type ClusterCreationParameters struct {
	Name             string `json:"Name"`
	Identity         string `json:"Identity"`
	Flavor           uint   `json:"Flavor"`
	Complexity       uint   `json:"Complexity"`
	Cidr             string `json:"Cidr"`
	Nodes            uint   `json:"Nodes"`
	Masters          uint   `json:"Masters"`
	DefaultGateway   string `json:"DefaultGateway"`
	OperatorUsername string `json:"OperatorUsername"`
	GwTemplate       string `json:"GwTemplate"`
	NodeTemplate     string `json:"NodeTemplate"`
	MasterTemplate   string `json:"MasterTemplate"`

	CreationDate string `json:"CreationDate"`

	GwDiskSize     uint `json:"GwDiskSize"`
	NodeDiskSize   uint `json:"NodeDiskSize"`
	MasterDiskSize uint `json:"MasterDiskSize"`

	GwOsPublisher string `json:"GwOsPublisher"`
	GwOsOffer     string `json:"GwOsOffer"`
	GwOsSku       string `json:"GwOsSku"`
	GwOsVersion   string `json:"GwOsVersion"`

	NodeOsPublisher string `json:"NodeOsPublisher"`
	NodeOsOffer     string `json:"NodeOsOffer"`
	NodeOsSku       string `json:"NodeOsSku"`
	NodeOsVersion   string `json:"NodeOsVersion"`

	MasterOsPublisher string `json:"MasterOsPublisher"`
	MasterOsOffer     string `json:"MasterOsOffer"`
	MasterOsSku       string `json:"MasterOsSku"`
	MasterOsVersion   string `json:"MasterOsVersion"`
	Region            string `json:"Region"`
}

type InitScriptParameters struct {
	Name             string `json:"Name"`
	Cidr             string `json:"Cidr"`
	Nodes            uint   `json:"Nodes"`
	Masters          uint   `json:"Masters"`
	DefaultGateway   string `json:"DefaultGateway"`
	OperatorUsername string `json:"OperatorUsername"`
	Region           string `json:"Region"`
}

type ClusterSizing struct {
	NumGateways   uint
	NumNodes      uint
	NumMasters    uint
	SizingGateway *abstract.HostSizingRequirements
	SizingNode    *abstract.HostSizingRequirements
	SizingMaster  *abstract.HostSizingRequirements
}

func getSizings(fla clusterflavor.Enum, com clustercomplexity.Enum) (*ClusterSizing, error) {
	switch fla {
	case clusterflavor.K8S:
		switch com {
		case clustercomplexity.Small:
			return &ClusterSizing{
				NumGateways: 1,
				NumNodes:    1,
				NumMasters:  1,
				SizingGateway: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  7.0,
					MaxRAMSize:  16.0,
					MinDiskSize: 50,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingNode: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingMaster: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
			}, nil
		case clustercomplexity.Normal:
			return &ClusterSizing{
				NumGateways: 1,
				NumNodes:    3,
				NumMasters:  2,
				SizingGateway: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  7.0,
					MaxRAMSize:  16.0,
					MinDiskSize: 50,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingNode: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingMaster: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
			}, nil
		case clustercomplexity.Large:
			return &ClusterSizing{
				NumGateways: 2,
				NumNodes:    7,
				NumMasters:  3,
				SizingGateway: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  7.0,
					MaxRAMSize:  16.0,
					MinDiskSize: 50,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingNode: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingMaster: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
			}, nil
		default:
			return nil, fmt.Errorf("unknown cluster complexity '%s'", com)
		}
	case clusterflavor.BOH:
		switch com {
		case clustercomplexity.Small:
			return &ClusterSizing{
				NumGateways: 1,
				NumNodes:    1,
				NumMasters:  1,
				SizingGateway: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  7.0,
					MaxRAMSize:  16.0,
					MinDiskSize: 50,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingNode: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingMaster: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
			}, nil
		case clustercomplexity.Normal:
			return &ClusterSizing{
				NumGateways: 1,
				NumNodes:    3,
				NumMasters:  2,
				SizingGateway: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  7.0,
					MaxRAMSize:  16.0,
					MinDiskSize: 50,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingNode: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingMaster: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
			}, nil
		case clustercomplexity.Large:
			return &ClusterSizing{
				NumGateways: 2,
				NumNodes:    7,
				NumMasters:  3,
				SizingGateway: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  7.0,
					MaxRAMSize:  16.0,
					MinDiskSize: 50,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingNode: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
				SizingMaster: &abstract.HostSizingRequirements{
					MinCores:    2,
					MaxCores:    4,
					MinRAMSize:  15.0,
					MaxRAMSize:  32.0,
					MinDiskSize: 80,
					MaxDiskSize: 0,
					MinGPU:      -1,
					MinCPUFreq:  0,
					Image:       "",
					Template:    "",
				},
			}, nil
		default:
			return nil, fmt.Errorf("unknown cluster complexity '%s'", com)
		}
	default:
		return nil, fmt.Errorf("unknown cluster flavor '%s'", fla)
	}
}

type persister func(req any, rootDir string, workDir string, rc []abstract.RenderedContent, hint any) error

func getPersister() persister {
	return fsPersister
}

func chainPersister(ps []persister) persister {
	return func(req any, rootDir string, workDir string, rc []abstract.RenderedContent, hint any) error {
		for _, p := range ps {
			err := p(req, rootDir, workDir, rc, hint)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func gitPersister(svc any, rootDir string, workDir string, rc []abstract.RenderedContent, hint any) error {
	// commit files to git
	var names []string
	for _, c := range rc {
		names = append(names, fmt.Sprintf("%s/%s", workDir, c.Name))
	}
	err := commitFiles(rootDir, names)
	if err != nil {
		return fmt.Errorf("error commiting files: %w", err)
	}

	// ok
	return nil
}

func consulPersister(svc any, rootDir string, workDir string, rc []abstract.RenderedContent, hint any) error {
	// if rendered content was right and consul is available, upload rendered content to consul
	for _, c := range rc {
		if svc, ok := svc.(iaas.Service); ok {
			otherCfg, xerr := svc.GetConfigurationOptions(context.Background())
			if xerr != nil {
				return fmt.Errorf("error getting configuration options: %w", xerr)
			}

			var terraformCfg stacks.TerraformOptions
			maybe, ok := otherCfg.Get("TerraformCfg")
			if ok {
				terraformCfg, ok = maybe.(stacks.TerraformOptions)
				if !ok {
					return fmt.Errorf("error getting terraform configuration options: %w", xerr)
				}
			}

			if terraformCfg.WithConsul {
				if workDir == rootDir {
					err := uploadToConsul(context.Background(), terraformCfg.ConsulURL, fmt.Sprintf("%s", c.Name), []byte(c.Content))
					if err != nil {
						return fmt.Errorf("error uploading to consul: %w", err)
					}
					continue
				}

				relative := strings.TrimPrefix(workDir, rootDir)
				relative = strings.TrimPrefix(relative, "/")

				err := uploadToConsul(context.Background(), terraformCfg.ConsulURL, fmt.Sprintf("%s/%s", relative, c.Name), []byte(c.Content))
				if err != nil {
					return fmt.Errorf("error uploading to consul: %w", err)
				}
			}
		}
	}

	return nil
}

func fileSystemPersister(svc any, rootDir string, workDir string, rc []abstract.RenderedContent, hint any) error {
	// render templates and write to filesystem
	for _, c := range rc {
		if c.Name == "" || c.Content == "" {
			return fmt.Errorf("invalid rendered content: %v", c)
		}
		f, err := os.Create(fmt.Sprintf("%s/%s", workDir, c.Name))
		if err != nil {
			return fmt.Errorf("error writing terraform files: %w", err)
		}
		err = template.Must(template.New("init").Parse(c.Content)).Execute(f, hint)
		if err != nil {
			return fmt.Errorf("error executing children template: %w", err)
		}
		err = f.Close()
		if err != nil {
			return fmt.Errorf("error closing children template: %w", err)
		}
	}

	// ok
	return nil
}

// fsPersister is a persister that writes the rendered content to the filesystem
func fsPersister(svc any, rootDir string, workDir string, rc []abstract.RenderedContent, hint any) error {
	return chainPersister([]persister{fileSystemPersister, consulPersister})(svc, rootDir, workDir, rc, hint)
}

func renderTerraformDiskAttachmentFromFiles(inctx context.Context, svc iaas.Service, directory string, tfg TfVolume, host resources.Host) error {
	workDir := directory

	type Extra struct {
		DiskName    string
		DiskId      string
		MachineName string
		MachineId   string
	}
	ctf, xerr := svc.Render(inctx, abstract.VolumeAttachmentResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	hID, _ := host.GetID()
	ctf[0].Name = fmt.Sprintf("attachment-%s-%s.tf", host.GetName(), tfg.Name)
	err := fsPersister(svc, directory, workDir, ctf, Extra{
		DiskName:    tfg.Name,
		DiskId:      tfg.Identity,
		MachineName: host.GetName(),
		MachineId:   hID,
	})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	return nil
}

func renderTerraformRuleFromFiles(inctx context.Context, svc iaas.Service, directory string, tfg TfSecurityGroup, rule *abstract.SecurityGroupRule) error {
	tfg.networkName = rule.Network
	if tfg.networkName == "" {
		return fmt.Errorf("network name is empty")
	}

	// join workDir with the module network name
	workDir := filepath.Join(directory, fmt.Sprintf("customcluster_%s", tfg.networkName))

	type Extra struct {
		RuleName  string
		Priority  int
		Direction string
		Protocol  string
		PortRange string
	}
	ctf, xerr := svc.Render(inctx, abstract.FirewallRuleResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	ctf[0].Name = fmt.Sprintf("firewallrule-%s.tf", tfg.Name)
	err := fsPersister(svc, directory, workDir, ctf, Extra{
		RuleName:  tfg.Name,
		Priority:  2000 + mrand.Intn(1000), // FIXME: This has to change, not only we have to keep track of ALL priorities, the USERS also have to know this information and be able to set them
		Direction: "Inbound",
		Protocol:  rule.Protocol,
		PortRange: fmt.Sprintf("%d-%d", rule.PortTo, rule.PortTo),
	})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	return nil
}
func renderTerraformSGFromFiles(inctx context.Context, svc iaas.Service, directory string, networkID, name, description string, rules abstract.SecurityGroupRules) error {
	netName := networkID
	if strings.HasPrefix(networkID, "network-") {
		netName = strings.TrimPrefix(networkID, "network-")
	}

	// join workDir with the module network name
	workDir := filepath.Join(directory, fmt.Sprintf("customcluster_%s", netName))

	type Extra struct {
		SecurityGroupName string
	}
	ctf, xerr := svc.Render(inctx, abstract.FirewallResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	ctf[0].Name = fmt.Sprintf("secgroup-%s.tf", name)
	err := fsPersister(svc, directory, workDir, ctf, Extra{SecurityGroupName: name})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	return nil
}

func renderTerraformHostFromFiles(inctx context.Context, svc iaas.Service, directory string, req abstract.HostRequest) error {
	// join workDir with the module network name
	workDir := filepath.Join(directory, fmt.Sprintf("customcluster_%s", req.SubnetNames[0]))

	type Extra struct {
		MachineName string
		TimeStamp   string
		NetworkName string
		Tags        map[string]string
	}
	ctf, xerr := svc.Render(inctx, abstract.HostResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	ctf[0].Name = fmt.Sprintf("machine-%s.tf", req.HostName)
	sparks := req.HostName
	if strings.HasPrefix(req.HostName, "gw-") {
		sparks = "gw"
	}
	ctf[1].Name = fmt.Sprintf("machine-tags-%s.tf", sparks)
	err := fsPersister(svc, directory, workDir, ctf, Extra{MachineName: sparks, TimeStamp: time.Now().Format(time.RFC3339), NetworkName: req.SubnetNames[0], Tags: make(map[string]string)})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	return nil
}

func renderTerraformBucketFromFiles(inctx context.Context, svc iaas.Service, directory string, req string) error {
	cfg, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	acfg, xerr := svc.GetAuthenticationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting authentication options: %w", xerr)
	}

	// join workDir with the module network name
	workDir := directory

	type Extra struct {
		Name           string
		StorageAccount string
		Region         string
	}

	// get the last 24 characters of the bucket name
	sac := cfg.GetString("MetadataBucketName")
	sacn := sac[len(sac)-24:]

	ctf, xerr := svc.Render(inctx, abstract.ObjectStorageBucketResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	ctf[1].Name = fmt.Sprintf("bucket-%s.tf", req)
	err := fsPersister(svc, workDir, workDir, ctf, Extra{Name: req, StorageAccount: sacn, Region: acfg.GetString("Region")})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	return nil
}

func renderTerraformVolumeFromFiles(inctx context.Context, svc iaas.Service, directory string, req abstract.VolumeRequest) error {
	cfg, xerr := svc.GetAuthenticationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	// join workDir with the module network name
	workDir := directory

	type Extra struct {
		Name      string
		Size      int
		TimeStamp string
		Region    string
	}
	ctf, xerr := svc.Render(inctx, abstract.VolumeResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	ctf[1].Name = fmt.Sprintf("disk-%s.tf", req.Name)
	err := fsPersister(svc, workDir, workDir, ctf, Extra{Name: req.Name, TimeStamp: time.Now().Format(time.RFC3339), Size: req.Size, Region: cfg.GetString("Region")})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	return nil
}

func renderTerraformNetworkFromFiles(inctx context.Context, svc iaas.Service, directory string, req abstract.NetworkRequest) error {
	cfg, xerr := svc.GetAuthenticationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	otherCfg, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	var terraformCfg stacks.TerraformOptions
	maybe, ok := otherCfg.Get("TerraformCfg")
	if ok {
		terraformCfg, ok = maybe.(stacks.TerraformOptions)
		if !ok {
			return fmt.Errorf("error getting terraform configuration options: %w", xerr)
		}
	}

	consulURL := terraformCfg.ConsulURL

	// join workDir with the module network name
	workDir := filepath.Join(directory, fmt.Sprintf("customcluster_%s", req.Name))
	err := os.MkdirAll(workDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating terraform directory: %w", err)
	}

	ctp, xerr := svc.Render(inctx, abstract.ProviderResource, "customcluster", cfg.(providers.ConfigMap))
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, directory, ctp, nil)
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	type Extra struct {
		Name string
		Tags map[string]string
	}

	ctc, xerr := svc.Render(inctx, abstract.ClusterResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, ctc, Extra{Name: "gw"})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	ctf, xerr := svc.Render(inctx, abstract.FirewallResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, ctf, Extra{Name: req.Name})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	ctv, xerr := svc.Render(inctx, abstract.VariableResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, ctv, nil)
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	cto, xerr := svc.Render(inctx, abstract.OutputResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, cto, nil)
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	if consulURL != "" {
		backend := map[string]any{
			"custom": "backend.tf",
			"target": fmt.Sprintf("%s-backend.tf", req.Name),
		}
		cti, xerr := svc.Render(inctx, abstract.CustomResource, "customcluster", backend)
		if xerr != nil {
			return fmt.Errorf("error rendering terraform files: %w", xerr)
		}
		err = fsPersister(svc, directory, directory, cti, terraformCfg)
		if err != nil {
			return fmt.Errorf("error persisting terraform files: %w", err)
		}
	}

	// cidr operations, we need to get the default gateway
	gwroot, _, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fmt.Errorf("error parsing CIDR: %w", err)
	}

	lastByte := byte(4) // we want to start at 4, so we can use 1,2,3 for other things

	// now increment the ip address by last_byte, only if there is no overflows
	if gwroot[3] < lastByte { // if there is no overflow
		gwroot[3] = gwroot[3] + lastByte
	} else {
		gwroot[3] = lastByte
	}

	theRegion := cfg.GetString("Region")
	if theRegion == "" {
		return fmt.Errorf("error getting region")
	}

	initScript := map[string]any{
		"custom": "init.sh",
		"target": fmt.Sprintf("%s-init.sh", req.Name),
	}
	cti, xerr := svc.Render(inctx, abstract.CustomResource, "customcluster", initScript)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, cti, InitScriptParameters{
		Name:           req.Name,
		Cidr:           req.CIDR,
		Region:         theRegion,
		DefaultGateway: gwroot.String(),
	})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	extra := map[string]any{
		"custom": "gw-init.sh",
		"target": fmt.Sprintf("%s-gw-init.sh", req.Name),
	}
	cti, xerr = svc.Render(inctx, abstract.CustomResource, "customcluster", extra)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, cti, InitScriptParameters{
		Name:           req.Name,
		Cidr:           req.CIDR,
		Region:         theRegion,
		DefaultGateway: gwroot.String(),
	})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	extra = map[string]any{
		"custom": "cluster-variables.tfvars",
	}
	cti, xerr = svc.Render(inctx, abstract.CustomResource, "customcluster", extra)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = os.WriteFile(fmt.Sprintf("%s/%s-variables.tmp", workDir, req.Name), []byte(cti[0].Content), 0666)
	if err != nil {
		return fmt.Errorf("error writing terraform files: %w", err)
	}

	return nil
}

func renderTerraformSubNetworkFromFiles(inctx context.Context, svc iaas.Service, directory string, req abstract.SubnetRequest) error {
	cfg, xerr := svc.GetAuthenticationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	otherCfg, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	var terraformCfg stacks.TerraformOptions
	maybe, ok := otherCfg.Get("TerraformCfg")
	if ok {
		terraformCfg, ok = maybe.(stacks.TerraformOptions)
		if !ok {
			return fmt.Errorf("error getting terraform configuration options: %w", xerr)
		}
	}

	consulURL := terraformCfg.ConsulURL
	workDir := directory

	// join workDir with the cluster name
	workDir = filepath.Join(workDir, fmt.Sprintf("customcluster_%s", req.Name))
	err := os.MkdirAll(workDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating terraform directory: %w", err)
	}

	ctp, xerr := svc.Render(inctx, abstract.ProviderResource, "customcluster", cfg.(providers.ConfigMap))
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, directory, ctp, nil)
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	type Extra struct {
		Name string
		Tags map[string]string
	}

	ctc, xerr := svc.Render(inctx, abstract.ClusterResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, ctc, Extra{Name: "gw"})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	ctf, xerr := svc.Render(inctx, abstract.FirewallResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, ctf, Extra{Name: req.Name})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	ctv, xerr := svc.Render(inctx, abstract.VariableResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, ctv, nil)
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	cto, xerr := svc.Render(inctx, abstract.OutputResource, "customcluster", nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, cto, nil)
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	if consulURL != "" {
		backend := map[string]any{
			"custom": "backend.tf",
			"target": fmt.Sprintf("%s-backend.tf", req.Name),
		}
		cti, xerr := svc.Render(inctx, abstract.CustomResource, "customcluster", backend)
		if xerr != nil {
			return fmt.Errorf("error rendering terraform files: %w", xerr)
		}
		err = fsPersister(svc, directory, directory, cti, terraformCfg)
		if err != nil {
			return fmt.Errorf("error persisting terraform files: %w", err)
		}
	}

	// cidr operations, we need to get the default gateway
	gwroot, _, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fmt.Errorf("error parsing CIDR: %w", err)
	}

	lastByte := byte(4) // we want to start at 4, so we can use 1,2,3 for other things

	// now increment the ip address by last_byte, only if there is no overflows
	if gwroot[3] < lastByte { // if there is no overflow
		gwroot[3] = gwroot[3] + lastByte
	} else {
		gwroot[3] = lastByte
	}

	theRegion := cfg.GetString("Region")
	if theRegion == "" {
		return fmt.Errorf("error getting region")
	}

	initScript := map[string]any{
		"custom": "init.sh",
		"target": fmt.Sprintf("%s-init.sh", req.Name),
	}
	cti, xerr := svc.Render(inctx, abstract.CustomResource, "customcluster", initScript)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, cti, InitScriptParameters{
		Name:             req.Name,
		Cidr:             req.CIDR,
		Region:           theRegion,
		DefaultGateway:   gwroot.String(),
		OperatorUsername: "safescale",
	})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	please := map[string]any{
		"custom": "gw-init.sh",
		"target": fmt.Sprintf("%s-gw-init.sh", req.Name),
	}
	cti, xerr = svc.Render(inctx, abstract.CustomResource, "customcluster", please)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, cti, InitScriptParameters{
		Name:             req.Name,
		Cidr:             req.CIDR,
		Region:           theRegion,
		DefaultGateway:   gwroot.String(),
		OperatorUsername: "safescale",
	})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	please = map[string]any{
		"custom": "cluster-variables.tfvars",
	}
	cti, xerr = svc.Render(inctx, abstract.CustomResource, "customcluster", please)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = os.WriteFile(fmt.Sprintf("%s/%s-variables.tmp", workDir, req.Name), []byte(cti[0].Content), 0666)
	if err != nil {
		return fmt.Errorf("error writing terraform files: %w", err)
	}

	return nil
}

// renderTerraformCustomClusterFromFiles renders the terraform files from the given directory
// returns an error if there is a problem rendering the files
func renderTerraformCustomClusterFromFiles(inctx context.Context, svc iaas.Service, directory string, req abstract.ClusterRequest) error {
	cfg, xerr := svc.GetAuthenticationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	otherCfg, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	var terraformCfg stacks.TerraformOptions
	maybe, ok := otherCfg.Get("TerraformCfg")
	if ok {
		terraformCfg, ok = maybe.(stacks.TerraformOptions)
		if !ok {
			return fmt.Errorf("error getting terraform configuration options: %w", xerr)
		}
	}

	defaultSizings, err := getSizings(req.Flavor, req.Complexity)
	if err != nil {
		return err
	}

	req.InitialMasterCount = defaultSizings.NumMasters
	req.InitialNodeCount = defaultSizings.NumNodes

	consulURL := terraformCfg.ConsulURL
	root := "customcluster"

	// join workDir with the module network name
	workDir := filepath.Join(directory, fmt.Sprintf("customcluster_%s", req.Name))
	err = os.MkdirAll(workDir, 0755)
	if err != nil {
		return fmt.Errorf("error creating terraform directory: %w", err)
	}

	ctp, xerr := svc.Render(inctx, abstract.ProviderResource, root, cfg.(providers.ConfigMap))
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, directory, ctp, nil)
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	type Extra struct {
		Name string
		Tags map[string]string
	}

	ctc, xerr := svc.Render(inctx, abstract.ClusterResource, root, nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, ctc, Extra{Name: "gw"})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	ctf, xerr := svc.Render(inctx, abstract.FirewallResource, root, nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, ctf, Extra{Name: req.Name})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	ctv, xerr := svc.Render(inctx, abstract.VariableResource, root, nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, ctv, nil)
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	cto, xerr := svc.Render(inctx, abstract.OutputResource, root, nil)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, cto, nil)
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	if consulURL != "" {
		backend := map[string]any{
			"custom": "backend.tf",
			"target": fmt.Sprintf("%s-backend.tf", req.Name),
		}
		cti, xerr := svc.Render(inctx, abstract.CustomResource, root, backend)
		if xerr != nil {
			return fmt.Errorf("error rendering terraform files: %w", xerr)
		}
		err = fsPersister(svc, directory, directory, cti, terraformCfg)
		if err != nil {
			return fmt.Errorf("error persisting terraform files: %w", err)
		}
	}

	// cidr operations, we need to get the default gateway
	gwroot, _, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fmt.Errorf("error parsing CIDR: %w", err)
	}

	lastByte := byte(4) // we want to start at 4, so we can use 1,2,3 for other things

	// now increment the ip address by last_byte, only if there is no overflows
	if gwroot[3] < lastByte { // if there is no overflow
		gwroot[3] = gwroot[3] + lastByte
	} else {
		gwroot[3] = lastByte
	}

	theRegion := cfg.GetString("Region")
	if theRegion == "" {
		return fmt.Errorf("error getting region")
	}

	initScript := map[string]any{
		"custom": "init.sh",
		"target": fmt.Sprintf("%s-init.sh", req.Name),
	}
	cti, xerr := svc.Render(inctx, abstract.CustomResource, root, initScript)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, cti, InitScriptParameters{
		Name:           req.Name,
		Cidr:           req.CIDR,
		Region:         theRegion,
		DefaultGateway: gwroot.String(),
	})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	extra := map[string]any{
		"custom": "gw-init.sh",
		"target": fmt.Sprintf("%s-gw-init.sh", req.Name),
	}
	cti, xerr = svc.Render(inctx, abstract.CustomResource, root, extra)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = fsPersister(svc, directory, workDir, cti, InitScriptParameters{
		Name:           req.Name,
		Cidr:           req.CIDR,
		Region:         theRegion,
		DefaultGateway: gwroot.String(),
	})
	if err != nil {
		return fmt.Errorf("error persisting terraform files: %w", err)
	}

	extra = map[string]any{
		"custom": "cluster-variables.tfvars",
	}
	cti, xerr = svc.Render(inctx, abstract.CustomResource, root, extra)
	if xerr != nil {
		return fmt.Errorf("error rendering terraform files: %w", xerr)
	}
	err = os.WriteFile(fmt.Sprintf("%s/%s-variables.tmp", workDir, req.Name), []byte(cti[0].Content), 0666)
	if err != nil {
		return fmt.Errorf("error writing terraform files: %w", err)
	}

	for i := 1; i <= int(req.InitialMasterCount); i++ {
		err = renderTerraformHostFromFiles(inctx, svc, directory, abstract.HostRequest{
			HostName:    fmt.Sprintf("%s-master-%d", req.Name, i),
			SubnetNames: []string{req.Name},
		})
		if err != nil {
			return fmt.Errorf("failed to render terraform host (master): %w", err)
		}
	}

	for i := 1; i <= int(req.InitialNodeCount); i++ {
		err = renderTerraformHostFromFiles(inctx, svc, directory, abstract.HostRequest{
			HostName:    fmt.Sprintf("%s-node-%d", req.Name, i),
			SubnetNames: []string{req.Name},
		})
		if err != nil {
			return fmt.Errorf("failed to render terraform host (node): %w", err)
		}
	}

	return nil
}

func gitRevert(inctx context.Context, workPath string) error {
	r, err := git.PlainOpen(workPath)
	if err != nil {
		return err
	}

	w, err := r.Worktree()
	if err != nil {
		return err
	}

	err = w.Reset(&git.ResetOptions{
		Mode: git.HardReset,
	})
	if err != nil {
		return err
	}

	err = w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName("refs/heads/master"),
	})
	if err != nil {
		return err
	}

	return nil
}

func gitCommit(aWorkPath string) error {
	repo, err := git.PlainOpen(aWorkPath)
	if err != nil {
		return err
	}

	wt, err := repo.Worktree()
	if err != nil {
		return err
	}

	st, err := wt.Status()
	if err != nil {
		return err
	}

	for k, v := range st {
		if v.Worktree == git.Modified || v.Worktree == git.Copied || v.Worktree == git.Renamed || v.Worktree == git.Untracked {
			_, err := wt.Add(k)
			if err != nil {
				return err
			}
		}
		if v.Worktree == git.Deleted {
			_, err := wt.Remove(k)
			if err != nil {
				return err
			}
		}
	}

	// Commits all changed files
	_, err = wt.Commit(fmt.Sprintf("Commit all changed files"), &git.CommitOptions{
		Author: &object.Signature{
			Name:  "safescale operator",
			Email: "safescale@safescale.org",
			When:  time.Now(),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func applyTerraform(inctx context.Context, svc iaas.Service, execPath string, aWorkPath string) (_ func() error, ferr error) {
	emptyCallback := func() error {
		return nil
	}

	callback := func() error {
		if ferr != nil {
			logrus.Warningf("Running rollback 1/3")
			err := gitRevert(inctx, aWorkPath)
			if err != nil {
				return err
			}

			logrus.Warningf("Running rollback 2/3")
			tf, err := tfexec.NewTerraform(aWorkPath, execPath)
			if err != nil {
				return fmt.Errorf("error in rollback: running NewTerraform: %w", err)
			}

			logrus.Warningf("Running rollback 3/3")
			err = tf.Apply(inctx)
			if err != nil {
				logrus.Warningf("error in rollback: applying terraform in %s: %s", aWorkPath, err.Error())
			}

			if err != nil {
				logrus.Warningf("Running rollback 4/3, sleep 180s")
				time.Sleep(180 * time.Second)
				err = tf.Apply(inctx)
				if err != nil {
					return fmt.Errorf("error in rollback: applying terraform in %s: %w", aWorkPath, err)
				}
			}

			return nil
		}
		return nil
	}

	defer func() {
		if ferr == nil {
			err := gitCommit(aWorkPath)
			if err != nil {
				logrus.Errorf("error commiting terraform changes: %s", err.Error())
			}
		}
	}()

	cfg, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "error recovering cfg")
	}

	maybe, there := cfg.Get("TerraformCfg")
	if !there {
		return nil, fail.NewError("terraform configuration not found")
	}

	_, ok := maybe.(stacks.TerraformOptions)
	if !ok {
		return nil, fail.NewError("unexpected cast problem")
	}

	workingDir, err := filepath.Abs(aWorkPath)
	if err != nil {
		return callback, fmt.Errorf("error running NewTerraform: %w", err)
	}

	_, err = os.Stat(aWorkPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return callback, err
		}
		_ = os.Mkdir(aWorkPath, 0750)
	}

	tf, err := tfexec.NewTerraform(workingDir, execPath)
	if err != nil {
		return callback, fmt.Errorf("error running NewTerraform: %w", err)
	}

	err = tf.Init(inctx, tfexec.Upgrade(true), tfexec.Reconfigure(true))
	if err != nil {
		return callback, fmt.Errorf("error running Init upgrade: %w", err)
	}

	// validate the terraform plan
	_, err = tf.Validate(inctx)
	if err != nil {
		return callback, fmt.Errorf("error validating terraform: %w", err)
	}

	err = tf.Apply(inctx)
	if err != nil {
		return callback, fmt.Errorf("error applying terraform in %s: %w", workingDir, err)
	}

	// If we are here, terraform apply was successful, no need to revert git changes, but we issue a warning if there is a problem with the backup of the state

	// get terraform state
	backup, err := tf.StatePull(inctx)
	if err != nil {
		return emptyCallback, fmt.Errorf("error running StatePull: %w", err)
	}

	// write terraform state to file
	err = os.WriteFile(filepath.Join(aWorkPath, "tfstate.backup"), []byte(backup), 0644)
	if err != nil {
		return emptyCallback, err
	}

	return emptyCallback, nil
}

func createTerraformSG(inctx context.Context, svc iaas.Service, execPath string, aWorkPath string) (_ func() error, ferr error) {
	clean, err := applyTerraform(inctx, svc, execPath, aWorkPath)
	if err != nil {
		return clean, err
	}

	return func() error {
		return nil
	}, nil
}

func createTerraformVolume(inctx context.Context, svc iaas.Service, execPath string, aWorkPath string, req abstract.VolumeRequest) (_ func() error, ferr error) {
	clean, err := applyTerraform(inctx, svc, execPath, aWorkPath)
	if err != nil {
		return clean, err
	}

	return func() error {
		return nil
	}, nil
}

func createTerraformHost(inctx context.Context, svc iaas.Service, execPath string, aWorkPath string, req abstract.HostRequest) (_ func() error, ferr error) {
	clean, err := applyTerraform(inctx, svc, execPath, aWorkPath)
	if err != nil {
		return clean, err
	}

	return func() error {
		return nil
	}, nil
}

func createTerraformNetwork(inctx context.Context, svc iaas.Service, execPath string, aWorkPath string, req abstract.NetworkRequest, reqsn abstract.SubnetRequest) (_ func() error, ferr error) {
	clean, err := applyTerraform(inctx, svc, execPath, aWorkPath)
	if err != nil {
		return clean, err
	}

	return func() error {
		return nil
	}, nil
}

func createTerraformSubNetwork(inctx context.Context, svc iaas.Service, execPath string, aWorkPath string, req abstract.SubnetRequest) (_ func() error, ferr error) {
	clean, err := applyTerraform(inctx, svc, execPath, aWorkPath)
	if err != nil {
		return clean, err
	}

	return func() error {
		return nil
	}, nil
}

// createTerraformCluster creates a Terraform cluster
// It returns a callback function to be called in case of error, and an error
// The callback function is used to clean resources
// The error is the error that occurred
// If no error occurred, the callback function is nil
func createTerraformCluster(inctx context.Context, svc iaas.Service, execPath string, aWorkPath string, req abstract.ClusterRequest) (_ func() error, ferr error) {
	clean, err := applyTerraform(inctx, svc, execPath, aWorkPath)
	if err != nil {
		return clean, err
	}

	return func() error {
		return nil
	}, nil
}

type Config struct {
	LogLevel string `hcl:"log_level"`
}

type ConfigInt struct {
	Threshold int `hcl:"power"`
}

func commitFiles(root string, paths []string) error {
	// Opens an already existing repository.
	r, err := git.PlainOpen(root)
	if err != nil {
		return err
	}

	w, err := r.Worktree()
	if err != nil {
		return err
	}

	for _, aPath := range paths {
		// convert from absolute path to relative path
		relative := strings.TrimPrefix(aPath, root)
		relative = strings.TrimPrefix(relative, "/")

		_, err = w.Add(relative)
		if err != nil {
			return err
		}
	}

	// Commit as safescale operator
	commit, err := w.Commit(fmt.Sprintf("updated %s", paths), &git.CommitOptions{
		Author: &object.Signature{
			Name:  "safescale operator",
			Email: "safescale@safescale.org",
			When:  time.Now(),
		},
	})
	if err != nil {
		return err
	}

	// Prints the current HEAD to verify that all worked well.
	_, err = r.CommitObject(commit)
	if err != nil {
		return err
	}

	return nil
}

func prepareTerraformHostVars(inctx context.Context, svc iaas.Service, aworkingDir string, req abstract.HostRequest) error {
	return nil
}

func prepareTerraformNetworkVars(inctx context.Context, svc iaas.Service, aworkingDir string, req abstract.NetworkRequest, snreq abstract.SubnetRequest) error {
	cfg, xerr := svc.GetAuthenticationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	opts, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	// cidr operations, we need to get the default gateway
	gwroot, _, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fmt.Errorf("error parsing CIDR: %w", err)
	}
	gwroot[3] = gwroot[3] + 4

	workingDir := filepath.Join(aworkingDir, fmt.Sprintf("customcluster_%s", req.Name))

	// all this should be a function
	ut, err := template.ParseFiles(filepath.Join(workingDir, fmt.Sprintf("%s-variables.tmp", req.Name)))
	if err != nil {
		return fmt.Errorf("error parsing files: %w", err)
	}
	f, err := os.Create(filepath.Join(aworkingDir, fmt.Sprintf("%s-rendered.tf", req.Name)))
	if err != nil {
		return fmt.Errorf("error creating masters template: %w", err)
	}

	// delete tmp file
	defer func(name string) {
		_ = os.Remove(name)
	}(filepath.Join(workingDir, fmt.Sprintf("%s-variables.tmp", req.Name)))

	theRegion := cfg.GetString("Region")
	if theRegion == "" {
		return fmt.Errorf("region cannot be empty")
	}

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return fail.ConvertError(err)
	}

	var gwDiskSize uint
	var gwTemplate string
	if snreq.GwSizing != nil {
		bySizing, xerr := svc.FindTemplateBySizing(inctx, *snreq.GwSizing)
		if xerr != nil {
			return fmt.Errorf("error finding template: %w", xerr)
		}

		// if undefined template size, better to use the default one
		if bySizing.RAMSize != 0 {
			gwTemplate = bySizing.Name
		}

		gwDiskSize = uint(bySizing.DiskSize)
		if gwDiskSize == 0 {
			gwDiskSize = diskSizeChooser(0, 0)
		}
	} else {
		gwDiskSize = diskSizeChooser(0, 0)
	}

	osImg, xerr := svc.SearchImage(inctx, snreq.ImageRef)
	if xerr != nil {
		return xerr
	}

	gwDiskSize = diskSizeChooser(int(gwDiskSize), int(osImg.DiskSize))

	err = ut.Execute(f, NetworkCreationParameters{
		CreationDate:     time.Now().Format(time.RFC3339),
		OperatorUsername: opts.GetString("OperatorUsername"),
		Name:             req.Name,
		Identity:         uuid.String(),
		Cidr:             req.CIDR,
		DefaultGateway:   gwroot.String(),
		Region:           theRegion,
		GwDiskSize:       gwDiskSize,
		GwTemplate:       gwTemplate,
		GwOsPublisher:    osImg.Publisher,
		GwOsOffer:        osImg.Offer,
		GwOsSku:          osImg.Sku,
		GwOsVersion:      "latest",
	})
	if err != nil {
		return fmt.Errorf("error executing children template: %w", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("error executing children template: %w", err)
	}

	return nil
}

func prepareTerraformSubNetworkVars(inctx context.Context, svc iaas.Service, aworkingDir string, req abstract.SubnetRequest) error {
	cfg, xerr := svc.GetAuthenticationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting authentication options: %w", xerr)
	}

	cfgo, xerr := svc.GetConfigurationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	osImg, xerr := svc.SearchImage(inctx, req.ImageRef)
	if xerr != nil {
		return xerr
	}

	// cidr operations, we need to get the default gateway
	gwroot, _, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fmt.Errorf("error parsing CIDR: %w", err)
	}
	gwroot[3] = gwroot[3] + 4

	defaultSizings, err := getSizings(clusterflavor.BOH, clustercomplexity.Small)
	if err != nil {
		return err
	}
	tht, xerr := svc.ListTemplatesBySizing(inctx, *defaultSizings.SizingGateway, true)
	if xerr != nil {
		return fmt.Errorf("error listing templates: %w", xerr)
	}
	fmt.Printf("Template selected: %s\n", tht[0].Name)
	gwTemplate := tht[0].Name

	var gwDiskSize uint
	gwDiskSize = uint(tht[0].DiskSize)
	if gwDiskSize == 0 {
		gwDiskSize = diskSizeChooser(0, 0)
	}

	workingDir := filepath.Join(aworkingDir, fmt.Sprintf("customcluster_%s", req.Name))

	// all this should be a function
	ut, err := template.ParseFiles(filepath.Join(workingDir, fmt.Sprintf("%s-variables.tmp", req.Name)))
	if err != nil {
		return fmt.Errorf("error parsing files: %w", err)
	}
	f, err := os.Create(filepath.Join(aworkingDir, fmt.Sprintf("%s-rendered.tf", req.Name)))
	if err != nil {
		return fmt.Errorf("error creating masters template: %w", err)
	}

	// delete tmp file
	defer func(name string) {
		_ = os.Remove(name)
	}(filepath.Join(workingDir, fmt.Sprintf("%s-variables.tmp", req.Name)))

	theRegion := cfg.GetString("Region")
	if theRegion == "" {
		return fmt.Errorf("region cannot be empty")
	}

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return fail.ConvertError(err)
	}

	gwDiskSize = diskSizeChooser(int(gwDiskSize), int(osImg.DiskSize))

	err = ut.Execute(f, SubnetCreationParameters{
		Name:              req.Name,
		Cidr:              req.CIDR,
		Nodes:             defaultSizings.NumNodes,
		Masters:           defaultSizings.NumMasters,
		DefaultGateway:    gwroot.String(),
		OperatorUsername:  cfgo.GetString("OperatorUsername"),
		GwTemplate:        gwTemplate,
		Identity:          uuid.String(),
		CreationDate:      time.Now().Format(time.RFC3339),
		GwDiskSize:        gwDiskSize,
		GwOsPublisher:     osImg.Publisher,
		GwOsOffer:         osImg.Offer,
		GwOsSku:           osImg.Sku,
		GwOsVersion:       "latest",
		NodeOsPublisher:   osImg.Publisher,
		NodeOsOffer:       osImg.Offer,
		NodeOsSku:         osImg.Sku,
		NodeOsVersion:     "latest",
		MasterOsPublisher: osImg.Publisher,
		MasterOsOffer:     osImg.Offer,
		MasterOsSku:       osImg.Sku,
		MasterOsVersion:   "latest",
		Region:            theRegion,
	})
	if err != nil {
		return fmt.Errorf("error executing children template: %w", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("error executing children template: %w", err)
	}

	return nil
}

func prepareCustomClusterTerraformVars(inctx context.Context, svc iaas.Service, aworkingDir string, req abstract.ClusterRequest) error {
	cfg, xerr := svc.GetAuthenticationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	if req.OS == "" {
		return fmt.Errorf("no OS specified")
	}

	requested := req.OS

	osImg, xerr := svc.SearchImage(inctx, requested)
	if xerr != nil {
		return xerr
	}

	// cidr operations, we need to get the default gateway
	gwroot, _, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fmt.Errorf("error parsing CIDR: %w", err)
	}
	gwroot[3] = gwroot[3] + 4

	defaultSizings, err := getSizings(req.Flavor, req.Complexity)
	if err != nil {
		return err
	}
	tht, xerr := svc.ListTemplatesBySizing(inctx, *defaultSizings.SizingGateway, true)
	if xerr != nil {
		return fmt.Errorf("error listing templates: %w", xerr)
	}
	gwTemplate := tht[0].Name

	thm, xerr := svc.ListTemplatesBySizing(inctx, *defaultSizings.SizingMaster, true)
	if xerr != nil {
		return fmt.Errorf("error listing templates: %w", xerr)
	}
	otherTemplate := thm[0].Name

	workingDir := filepath.Join(aworkingDir, fmt.Sprintf("customcluster_%s", req.Name))

	// all this should be a function
	ut, err := template.ParseFiles(filepath.Join(workingDir, fmt.Sprintf("%s-variables.tmp", req.Name)))
	if err != nil {
		return fmt.Errorf("error parsing files: %w", err)
	}
	f, err := os.Create(filepath.Join(aworkingDir, fmt.Sprintf("%s-rendered.tf", req.Name)))
	if err != nil {
		return fmt.Errorf("error creating masters template: %w", err)
	}

	// delete tmp file
	defer func(name string) {
		_ = os.Remove(name)
	}(filepath.Join(workingDir, fmt.Sprintf("%s-variables.tmp", req.Name)))

	theRegion := cfg.GetString("Region")
	if theRegion == "" {
		return fmt.Errorf("region cannot be empty")
	}

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return fail.ConvertError(err)
	}

	err = ut.Execute(f, ClusterCreationParameters{
		CreationDate:      time.Now().Format(time.RFC3339),
		Name:              req.Name,
		Identity:          uuid.String(),
		Flavor:            uint(req.Flavor),
		Complexity:        uint(req.Complexity),
		Cidr:              req.CIDR,
		Nodes:             defaultSizings.NumNodes,
		Masters:           defaultSizings.NumMasters,
		DefaultGateway:    gwroot.String(),
		OperatorUsername:  req.OperatorUsername,
		GwTemplate:        gwTemplate,
		NodeTemplate:      otherTemplate,
		MasterTemplate:    otherTemplate,
		GwDiskSize:        diskSizeChooser(req.GatewaysDef.MinDiskSize, req.GatewaysDef.MaxDiskSize),
		NodeDiskSize:      diskSizeChooser(req.NodesDef.MinDiskSize, req.NodesDef.MaxDiskSize),
		MasterDiskSize:    diskSizeChooser(req.MastersDef.MinDiskSize, req.MastersDef.MaxDiskSize),
		GwOsPublisher:     osImg.Publisher,
		GwOsOffer:         osImg.Offer,
		GwOsSku:           osImg.Sku,
		GwOsVersion:       "latest",
		NodeOsPublisher:   osImg.Publisher,
		NodeOsOffer:       osImg.Offer,
		NodeOsSku:         osImg.Sku,
		NodeOsVersion:     "latest",
		MasterOsPublisher: osImg.Publisher,
		MasterOsOffer:     osImg.Offer,
		MasterOsSku:       osImg.Sku,
		MasterOsVersion:   "latest",
		Region:            theRegion,
	})
	if err != nil {
		return fmt.Errorf("error executing children template: %w", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("error executing children template: %w", err)
	}

	return nil
}

func prepareClusterTerraformVars(inctx context.Context, svc iaas.Service, aworkingDir string, req abstract.ClusterRequest) error {
	cfg, xerr := svc.GetAuthenticationOptions(inctx)
	if xerr != nil {
		return fmt.Errorf("error getting configuration options: %w", xerr)
	}

	if req.OS == "" {
		return fmt.Errorf("no OS specified")
	}

	requested := req.OS

	osImg, xerr := svc.SearchImage(inctx, requested)
	if xerr != nil {
		return xerr
	}

	// cidr operations, we need to get the default gateway
	gwroot, _, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fmt.Errorf("error parsing CIDR: %w", err)
	}
	gwroot[3] = gwroot[3] + 4

	defaultSizings, err := getSizings(req.Flavor, req.Complexity)
	if err != nil {
		return err
	}
	tht, xerr := svc.ListTemplatesBySizing(inctx, *defaultSizings.SizingGateway, true)
	if xerr != nil {
		return fmt.Errorf("error listing templates: %w", xerr)
	}
	gwTemplate := tht[0].Name

	thm, xerr := svc.ListTemplatesBySizing(inctx, *defaultSizings.SizingMaster, true)
	if xerr != nil {
		return fmt.Errorf("error listing templates: %w", xerr)
	}
	otherTemplate := thm[0].Name

	workingDir := filepath.Join(aworkingDir, "cluster")

	// all this should be a function
	ut, err := template.ParseFiles(filepath.Join(workingDir, fmt.Sprintf("%s-variables.tmp", req.Name)))
	if err != nil {
		return fmt.Errorf("error parsing files: %w", err)
	}
	f, err := os.Create(filepath.Join(aworkingDir, fmt.Sprintf("%s-rendered.tf", req.Name)))
	if err != nil {
		return fmt.Errorf("error creating masters template: %w", err)
	}

	// delete tmp file
	defer func(name string) {
		_ = os.Remove(name)
	}(filepath.Join(workingDir, fmt.Sprintf("%s-variables.tmp", req.Name)))

	theRegion := cfg.GetString("Region")
	if theRegion == "" {
		return fmt.Errorf("region cannot be empty")
	}

	uuid, err := uuidpkg.NewV4()
	if err != nil {
		return fail.ConvertError(err)
	}

	err = ut.Execute(f, ClusterCreationParameters{
		CreationDate:      time.Now().Format(time.RFC3339),
		Name:              req.Name,
		Identity:          uuid.String(),
		Flavor:            uint(req.Flavor),
		Complexity:        uint(req.Complexity),
		Cidr:              req.CIDR,
		Nodes:             defaultSizings.NumNodes,
		Masters:           defaultSizings.NumMasters,
		DefaultGateway:    gwroot.String(),
		OperatorUsername:  req.OperatorUsername,
		GwTemplate:        gwTemplate,
		NodeTemplate:      otherTemplate,
		MasterTemplate:    otherTemplate,
		GwDiskSize:        diskSizeChooser(req.GatewaysDef.MinDiskSize, req.GatewaysDef.MaxDiskSize),
		NodeDiskSize:      diskSizeChooser(req.NodesDef.MinDiskSize, req.NodesDef.MaxDiskSize),
		MasterDiskSize:    diskSizeChooser(req.MastersDef.MinDiskSize, req.MastersDef.MaxDiskSize),
		GwOsPublisher:     osImg.Publisher,
		GwOsOffer:         osImg.Offer,
		GwOsSku:           osImg.Sku,
		GwOsVersion:       "latest",
		NodeOsPublisher:   osImg.Publisher,
		NodeOsOffer:       osImg.Offer,
		NodeOsSku:         osImg.Sku,
		NodeOsVersion:     "latest",
		MasterOsPublisher: osImg.Publisher,
		MasterOsOffer:     osImg.Offer,
		MasterOsSku:       osImg.Sku,
		MasterOsVersion:   "latest",
		Region:            theRegion,
	})
	if err != nil {
		return fmt.Errorf("error executing children template: %w", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("error executing children template: %w", err)
	}

	return nil
}

func LoadTerraformHosts(inctx context.Context, svc iaas.Service) ([]resources.Host, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(inctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return []resources.Host{}, nil
		default:
			return nil, xerr
		}
	}

	var results []resources.Host

	maybe, xerr := svc.ExportFromState(inctx, abstract.HostResource, tfstate, &TfHost{}, "")
	if xerr != nil {
		return nil, xerr
	}
	casted := maybe.([]*TfHost)
	for _, v := range casted {
		v.svc = svc
		results = append(results, v)
	}

	return results, nil
}

func LoadTerraformSecurityGroup(inctx context.Context, svc iaas.Service, ref string) (*TfSecurityGroup, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	sgs, xerr := ListTerraformSGs(inctx, svc)
	if xerr != nil {
		return nil, xerr
	}

	for _, sg := range sgs {
		if sg.Name == ref || strings.Contains(sg.Name, fmt.Sprintf("-%s", ref)) {
			return sg, nil
		}
	}

	return nil, fail.NotFoundError("failed to find security group %s", ref)
}

func ListTerraformBuckets(inctx context.Context, svc iaas.Service) ([]*TfBucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(inctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return []*TfBucket{}, nil
		default:
			return nil, xerr
		}
	}

	var results []*TfBucket

	maybe, xerr := svc.ExportFromState(inctx, abstract.ObjectStorageBucketResource, tfstate, &TfBucket{}, "")
	if xerr != nil {
		return nil, xerr
	}

	results = maybe.([]*TfBucket)
	for _, res := range results {
		res.svc = svc
	}

	return results, nil
}
func ListTerraformVolumes(inctx context.Context, svc iaas.Service) ([]*TfVolume, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(inctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return []*TfVolume{}, nil
		default:
			return nil, xerr
		}
	}

	var results []*TfVolume

	maybe, xerr := svc.ExportFromState(inctx, abstract.VolumeResource, tfstate, &TfVolume{}, "")
	if xerr != nil {
		return nil, xerr
	}

	results = maybe.([]*TfVolume)
	for _, res := range results {
		res.svc = svc
	}

	return results, nil
}

func LoadTerraformVolume(inctx context.Context, svc iaas.Service, ref string) (*TfVolume, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(inctx)
	if xerr != nil {
		return nil, xerr
	}

	tfh, xerr := NewTerraformVolume(svc)
	if xerr != nil {
		return nil, xerr
	}

	maybe, xerr := svc.ExportFromState(inctx, abstract.VolumeResource, tfstate, tfh, ref)
	if xerr != nil {
		return nil, xerr
	}

	atf := maybe.(*TfVolume)
	return atf, nil
}

func LoadTerraformHost(inctx context.Context, svc iaas.Service, ref string) (resources.Host, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(inctx)
	if xerr != nil {
		return nil, xerr
	}

	tfh, xerr := NewTerraformHost(svc)
	if xerr != nil {
		return nil, xerr
	}

	maybe, xerr := svc.ExportFromState(inctx, abstract.HostResource, tfstate, tfh, ref)
	if xerr != nil {
		return nil, xerr
	}

	atf := maybe.(*TfHost)
	return atf, nil
}

func LoadTerraformBucket(inctx context.Context, svc iaas.Service, ref string) (resources.Bucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(inctx)
	if xerr != nil {
		return nil, xerr
	}

	tfh, xerr := NewTerraformBucket(svc)
	if xerr != nil {
		return nil, xerr
	}

	maybe, xerr := svc.ExportFromState(inctx, abstract.ObjectStorageBucketResource, tfstate, tfh, ref)
	if xerr != nil {
		return nil, xerr
	}

	atf := maybe.(*TfBucket)
	return atf, nil
}

func NewTfCluster(inctx context.Context, svc iaas.Service) (_ *TerraformCluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	_, cancel := context.WithCancel(inctx)
	defer cancel()

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	instance, xerr := NewTerraformCluster(svc)
	if xerr != nil {
		return nil, xerr
	}

	return instance, nil
}

func ListTerraformNetworks(inctx context.Context, svc iaas.Service) (_ []*TfNetwork, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	_, cancel := context.WithCancel(inctx)
	defer cancel()

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(inctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return []*TfNetwork{}, nil
		default:
			return nil, xerr
		}
	}

	var results []*TfNetwork

	// recover the subnet information
	maybe, xerr := svc.ExportFromState(inctx, abstract.NetworkResource, tfstate, &TfNetwork{}, "")
	if xerr != nil {
		logrus.Warningf("failure exporting from state: %v", xerr)
		return nil, xerr
	}

	results = maybe.([]*TfNetwork)
	for _, res := range results {
		res.svc = svc
	}

	return results, nil
}

func ListTerraformSGs(inctx context.Context, svc iaas.Service) ([]*TfSecurityGroup, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// first, read terraform status
	tfstate, xerr := svc.GetTerraformState(inctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return []*TfSecurityGroup{}, nil
		default:
			return nil, xerr
		}
	}

	var results []*TfSecurityGroup

	maybe, xerr := svc.ExportFromState(inctx, abstract.SecurityGroupResource, tfstate, &TfSecurityGroup{}, "")
	if xerr != nil {
		return nil, xerr
	}
	results = maybe.([]*TfSecurityGroup)

	for _, res := range results {
		res.svc = svc
	}

	return results, nil
}

func ListTerraformClusters(inctx context.Context, svc iaas.Service) (_ []*TfNetwork, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	tc, xerr := ListTerraformNetworks(inctx, svc)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return []*TfNetwork{}, nil
		default:
			return nil, fail.Wrap(xerr, "failed to list terraform clusters")
		}
	}

	var clusters []*TfNetwork
	for _, v := range tc {
		if _, ok := v.Tags["Kind"]; ok {
			if v.Tags["Kind"] == "Cluster" {
				clusters = append(clusters, v)
			}
		}
	}

	return clusters, nil
}

func LoadTerraformCluster(inctx context.Context, svc iaas.Service, name string) (_ *TerraformCluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	_, cancel := context.WithCancel(inctx)
	defer cancel()

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	clus, xerr := ListTerraformNetworks(inctx, svc)
	if xerr != nil {
		return nil, xerr
	}

	found := false
	for _, clu := range clus {
		if clu.Name == name || strings.Contains(clu.Name, fmt.Sprintf("-%s", name)) {
			found = true
			break
		}
	}

	if !found {
		return nil, fail.NotFoundError("cluster %s not found", name)
	}

	instance, xerr := NewTerraformCluster(svc)
	if xerr != nil {
		return nil, xerr
	}

	instance.Name = name

	return instance, nil
}

func LoadTerraformNetwork(inctx context.Context, svc iaas.Service, name string) (_ *TfNetwork, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	_, cancel := context.WithCancel(inctx)
	defer cancel()

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	instance, xerr := NewTerraformNetwork(svc)
	if xerr != nil {
		return nil, xerr
	}

	// first, read terraform status
	tfstate, xerr := instance.svc.GetTerraformState(inctx)
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = instance.svc.ExportFromState(inctx, abstract.NetworkResource, tfstate, instance, name)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failure exporting from terraform state")
	}

	return instance, nil
}
