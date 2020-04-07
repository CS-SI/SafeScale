package outscale

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/outscale/osc-sdk-go/oapi"
	"github.com/sirupsen/logrus"
)

//Credentials outscale credentials
type Credentials struct {
	AccessKey string
	SecretKey string
}

//ComputeConfiguration outscale compute configuration
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
	WhitelistTemplateRegexp *regexp.Regexp
	BlacklistTemplateRegexp *regexp.Regexp
	WhitelistImageRegexp    *regexp.Regexp
	BlacklistImageRegexp    *regexp.Regexp
}

//NetworConfiguration outscale network configuration
type NetworConfiguration struct {
	VPCName string
	VPCCIDR string
	VPCID   string
}

//StorageConfiguration outscale storage configuration
type StorageConfiguration struct {
	Type      string
	Endpoint  string
	AccessKey string
	SecretKey string
}

//MetadataConfiguration metadata storage configuration
type MetadataConfiguration struct {
	Type      string
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	CryptKey  string
}

//ConfigurationOptions outscale stack configuration options
type ConfigurationOptions struct {
	Identity      Credentials           `json:"identity,omitempty"`
	Compute       ComputeConfiguration  `json:"compute,omitempty"`
	Network       NetworConfiguration   `json:"network,omitempty"`
	Objectstorage StorageConfiguration  `json:"objectstorage,omitempty"`
	Metadata      MetadataConfiguration `json:"metadata,omitempty"`
}

//Stack Outscale Stack to adpat outscale IaaS API
type Stack struct {
	Options             ConfigurationOptions
	client              *oapi.Client
	CPUPerformanceMap   map[int]float32
	VolumeSpeedsMap     map[string]volumespeed.Enum
	configrationOptions *stacks.ConfigurationOptions
	deviceNames         []string
}

//New creates a new Stack
func New(options *ConfigurationOptions) (*Stack, error) {
	cfg := oapi.Config{
		AccessKey: options.Identity.AccessKey,
		SecretKey: options.Identity.SecretKey,
		Region:    options.Compute.Region,
		Service:   options.Compute.Service,
		URL:       options.Compute.URL,
	}
	client := oapi.NewClient(&cfg, nil)
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
		configrationOptions: &stacks.ConfigurationOptions{
			ProviderNetwork:           "",
			DNSList:                   options.Compute.DNSList,
			UseFloatingIP:             true,
			UseLayer3Networking:       true,
			UseNATService:             true,
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
	if err != nil || onet == nil { //Try to create the network
		onet, err = s.createVpc(s.Options.Network.VPCName, s.Options.Network.VPCCIDR)
		if err != nil {
			logrus.Errorf("%v", err)
			return err
		}
	}
	s.Options.Network.VPCID = onet.NetId

	return nil
}

func deviceNames() []string {
	var deviceNames []string
	for i := int('d'); i <= int('z'); i++ {
		deviceNames = append(deviceNames, fmt.Sprintf("xvd%s", string(i)))
	}
	return deviceNames
}

//ListRegions list available regions
func (s *Stack) ListRegions() ([]string, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	return []string{
		"cn-southeast-1",
		"eu-west-2",
		"us-east-2",
		"us-west-1",
	}, nil
}

//ListAvailabilityZones returns availability zone in a set
func (s *Stack) ListAvailabilityZones() (map[string]bool, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	resp, err := s.client.POST_ReadSubregions(oapi.ReadSubregionsRequest{})
	if err != nil {
		return nil, err
	}
	az := make(map[string]bool)
	for _, r := range resp.OK.Subregions {
		az[r.SubregionName] = true
	}
	return az, nil
}

// -----------------------------------------------------
// //TODO to be removed when outscale go sdk goes to v1
//-------------------------------------------------------

//UpdateSubnetRequest implements the service definition of UpdateSubnet
type UpdateSubnetRequest struct {
	DryRun              bool   `json:"DryRun,omitempty"`
	MapPublicIpOnLaunch bool   `json:"MapPublicIpOnLaunch"`
	SubnetId            string `json:"SubnetId,omitempty"`
}

//UpdateSubnetResponse implements the service definition of UpdateSubnetResponse
type UpdateSubnetResponse struct {
	ResponseContext oapi.ResponseContext `json:"ResponseContext,omitempty"`
	Subnet          oapi.Subnet          `json:"Subnet,omitempty"`
}

//POST_UpdateSubnetResponses holds responses of POST_UpdateSubnet
type POST_UpdateSubnetResponses struct {
	OK      *UpdateSubnetResponse
	Code400 *oapi.ErrorResponse
	Code401 *oapi.ErrorResponse
	Code409 *oapi.ErrorResponse
	Code500 *oapi.ErrorResponse
}

func checkErrorResponse(resp *http.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response error body %s", err)
	}

	reason, errFmt := fmtErrorResponse(body)
	if errFmt != nil {
		return fmt.Errorf("error formating error resonse %s", err)
	}

	return fmt.Errorf("error, status code %d, reason: %s", resp.StatusCode, reason)
}

func fmtErrorResponse(errBody []byte) (string, error) {
	result := &oapi.ErrorResponse{}
	err := json.Unmarshal(errBody, result)
	if err != nil {
		return "", err
	}

	errors, errPretty := json.MarshalIndent(result, "", "  ")
	if errPretty != nil {
		return "", err
	}

	return string(errors), nil
}

//UpdateSubnet update a subnet
func (s *Stack) updateSubnet(
	UpdateSubnetRequest UpdateSubnetRequest,
) (
	response *POST_UpdateSubnetResponses,
	err error,
) {
	path := s.client.GetConfig().ServiceURL() + "/UpdateSubnet"
	body := new(bytes.Buffer)
	err = json.NewEncoder(body).Encode(UpdateSubnetRequest)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", path, body)
	reqHeaders := make(http.Header)
	reqHeaders.Set("Content-Type", "application/json")
	req.Header = reqHeaders
	err = s.client.Sign(req, body.Bytes())
	if err != nil {
		return
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			logrus.Errorf("%v", err)
		}
	}()
	if resp.StatusCode != 200 {
		return nil, checkErrorResponse(resp)
	}
	response = &POST_UpdateSubnetResponses{}
	switch {
	case resp.StatusCode == 200:
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		result := &UpdateSubnetResponse{}
		err = json.Unmarshal(body, result)
		if err != nil {
			return nil, err
		}
		response.OK = result
	case resp.StatusCode == 400:
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		result := &oapi.ErrorResponse{}
		err = json.Unmarshal(body, result)
		if err != nil {
			return nil, err
		}
		response.Code400 = result
	case resp.StatusCode == 401:
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		result := &oapi.ErrorResponse{}
		err = json.Unmarshal(body, result)
		if err != nil {
			return nil, err
		}
		response.Code401 = result
	case resp.StatusCode == 409:
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		result := &oapi.ErrorResponse{}
		err = json.Unmarshal(body, result)
		if err != nil {
			return nil, err
		}
		response.Code409 = result
	case resp.StatusCode == 500:
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		result := &oapi.ErrorResponse{}
		err = json.Unmarshal(body, result)
		if err != nil {
			return nil, err
		}
		response.Code500 = result
	default:
		break
	}
	return
}
