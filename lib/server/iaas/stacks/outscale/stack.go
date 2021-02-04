package outscale

import (
	"context"
	"fmt"
	"regexp"

	"github.com/outscale-dev/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Credentials outscale credentials
type Credentials struct {
	AccessKey string
	SecretKey string
}

// ComputeConfiguration outscale compute configuration
type ComputeConfiguration struct {
	URL                     string
	Region                  string
	Subregion               string
	Service                 string
	DefaultImage            string
	DefaultVolumeSpeed      volumespeed.Enum
	DefaultTenancy          string
	DNSList                 []string
	OperatorUsername        string
	MaxLifetimeInHours      string
	WhitelistTemplateRegexp *regexp.Regexp
	BlacklistTemplateRegexp *regexp.Regexp
	WhitelistImageRegexp    *regexp.Regexp
	BlacklistImageRegexp    *regexp.Regexp
}

// NetworConfiguration outscale network configuration
type NetworConfiguration struct {
	VPCName string
	VPCCIDR string
	VPCID   string
}

// StorageConfiguration outscale storage configuration
type StorageConfiguration struct {
	Type      string
	Endpoint  string
	AccessKey string
	SecretKey string
}

// MetadataConfiguration metadata storage configuration
type MetadataConfiguration struct {
	Type      string
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	CryptKey  string
}

// ConfigurationOptions outscale stack configuration options
type ConfigurationOptions struct {
	Identity      Credentials           `json:"identity,omitempty"`
	Compute       ComputeConfiguration  `json:"compute,omitempty"`
	Network       NetworConfiguration   `json:"network,omitempty"`
	ObjectStorage StorageConfiguration  `json:"objectstorage,omitempty"`
	Metadata      MetadataConfiguration `json:"metadata,omitempty"`
}

// Stack Outscale Stack to adapt outscale IaaS API
type Stack struct {
	Options              ConfigurationOptions
	client               *osc.APIClient
	auth                 context.Context
	CPUPerformanceMap    map[int]float32
	VolumeSpeedsMap      map[string]volumespeed.Enum
	configurationOptions *stacks.ConfigurationOptions
	deviceNames          []string
}

// New creates a new Stack
func New(options *ConfigurationOptions) (*Stack, fail.Error) {
	client := osc.NewAPIClient(osc.NewConfiguration())
	auth := context.WithValue(
		context.Background(), osc.ContextAWSv4, osc.AWSv4{
			AccessKey: options.Identity.AccessKey,
			SecretKey: options.Identity.SecretKey,
		},
	)
	volumeSpeeds := map[string]volumespeed.Enum{
		"standard": volumespeed.COLD,
		"gp2":      volumespeed.HDD,
		"io1":      volumespeed.SSD,
	}
	s := Stack{
		Options:         *options,
		client:          client,
		VolumeSpeedsMap: volumeSpeeds,
		CPUPerformanceMap: map[int]float32{
			1: 3.0,
			2: 2.5,
			3: 2.0,
		},
		deviceNames: deviceNames(),
		configurationOptions: &stacks.ConfigurationOptions{
			ProviderNetwork:           "",
			DNSList:                   options.Compute.DNSList,
			UseFloatingIP:             true,
			UseLayer3Networking:       false,
			UseNATService:             false,
			ProviderName:              "outscale",
			BuildSubnetworks:          false,
			AutoHostNetworkInterfaces: false,
			VolumeSpeeds:              volumeSpeeds,
			DefaultImage:              options.Compute.DefaultImage,
			MetadataBucket:            options.Metadata.Bucket,
			OperatorUsername:          options.Compute.OperatorUsername,
			BlacklistImageRegexp:      options.Compute.BlacklistImageRegexp,
			BlacklistTemplateRegexp:   options.Compute.BlacklistTemplateRegexp,
			WhitelistImageRegexp:      options.Compute.WhitelistImageRegexp,
			WhitelistTemplateRegexp:   options.Compute.WhitelistTemplateRegexp,
		},
		auth: auth,
	}
	return &s, s.initDefaultNetwork()
}

func (s *Stack) initDefaultNetwork() error {
	if s.Options.Network.VPCID != "" {
		return nil
	}
	if s.Options.Network.VPCName == "" {
		s.Options.Network.VPCName = "safescale-vpc"
	}
	if s.Options.Network.VPCCIDR == "" {
		s.Options.Network.VPCCIDR = "192.168.0.0/16"
	}
	onet, err := s.getVpcByName(s.Options.Network.VPCName)
	if err != nil || onet == nil { // Try to create the network
		onet, err = s.createVpc(s.Options.Network.VPCName, s.Options.Network.VPCCIDR)
		if err != nil {
			return err
		}
	}
	s.Options.Network.VPCID = onet.NetId

	return nil
}

func deviceNames() []string {
	var deviceNames []string
	for i := int('d') - int('a'); i <= int('z')-int('a'); i++ {
		deviceNames = append(deviceNames, fmt.Sprintf("xvd%s", string('a'+rune(i))))
	}
	return deviceNames
}

// ListRegions list available regions
func (s *Stack) ListRegions() ([]string, fail.Error) {
	return []string{
		"cn-southeast-1",
		"eu-west-2",
		"us-east-2",
		"us-west-1",
	}, nil
}

// ListAvailabilityZones returns availability zone in a set
func (s *Stack) ListAvailabilityZones() (map[string]bool, fail.Error) {
	resp, _, err := s.client.SubregionApi.ReadSubregions(s.auth, nil)
	if err != nil {
		return nil, err
	}
	az := make(map[string]bool)
	for _, r := range resp.Subregions {
		az[r.SubregionName] = true
	}
	return az, nil
}
