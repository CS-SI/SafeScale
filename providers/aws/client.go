/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package aws

//go:generate rice embed-go
import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/pricing"
	"github.com/oscarpicas/SafeScale/providers/aws/s3"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/GeertJohan/go.rice"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	awss3 "github.com/aws/aws-sdk-go/service/s3"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeState"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/system"
)

// //Config AWS configurations
// type Config struct {
// 	ImageOwners    []string
// 	DefaultNetwork string
// }

//AuthOpts AWS credentials
type AuthOpts struct {
	// AWS Access key ID
	AccessKeyID string

	// AWS Secret Access Key
	SecretAccessKey string
	// The region to send requests to. This parameter is required and must
	// be configured globally or on a per-client basis unless otherwise
	// noted. A full list of regions is found in the "Regions and Endpoints"
	// document.
	//
	// @see http://docs.aws.amazon.com/general/latest/gr/rande.html
	//   AWS Regions and Endpoints
	Region string
	//Config *Config
}

// Retrieve returns nil if it successfully retrieved the value.
// Error is returned if the value were not obtainable, or empty.
func (o AuthOpts) Retrieve() (credentials.Value, error) {
	return credentials.Value{
		AccessKeyID:     o.AccessKeyID,
		SecretAccessKey: o.SecretAccessKey,
		ProviderName:    "internal",
	}, nil
}

// IsExpired returns if the credentials are no longer valid, and need
// to be retrieved.
func (o AuthOpts) IsExpired() bool {
	return false
}

// AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOpts) (*Client, error) {
	s, err := session.NewSession(&aws.Config{
		Region:      aws.String(opts.Region),
		Credentials: credentials.NewCredentials(opts),
	})
	if err != nil {
		return nil, err
	}
	sPricing, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-east-1"),
		Credentials: credentials.NewCredentials(opts),
	})
	if err != nil {
		return nil, err
	}
	box, err := rice.FindBox("scripts")
	if err != nil {
		return nil, err
	}
	userDataStr, err := box.String("userdata.sh")
	if err != nil {
		return nil, err
	}
	tpl, err := template.New("user_data").Parse(userDataStr)
	if err != nil {
		return nil, err
	}
	c := Client{
		Session:     s,
		EC2:         ec2.New(s),
		Pricing:     pricing.New(sPricing),
		AuthOpts:    opts,
		UserDataTpl: tpl,
	}
	//providers.InitializeBucket(&c)
	//c.CreateContainer("gpac.aws.networks")
	//c.CreateContainer("gpac.aws.wms")
	//c.CreateContainer("gpac.aws.volumes")

	return &c, nil
}

func wrapError(msg string, err error) error {
	if err == nil {
		return nil
	}
	if aerr, ok := err.(awserr.Error); ok {
		return fmt.Errorf("%s: cause by %s", msg, aerr.Message())
	}
	return err
}

// Build build a new Client from configuration parameter
func (c *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	tenantName, _ := params["name"].(string)
	_ = tenantName

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})
	_ = network

	accessKeyID, _ := identity["AccessKeyID"].(string)
	secretAccessKey, _ := identity["SecretAccessKey"].(string)
	identityEndpoint, _ := identity["EndPoint"].(string)
	_ = identityEndpoint

	region, _ := compute["Region"].(string)
	defaultImage, _ := compute["DefaultImage"]
	_ = defaultImage

	return AuthenticatedClient(
		AuthOpts{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
			Region:          region,
		},
	)

}

// CfgOptions configuration options
type CfgOptions struct {
	// Name of the provider (external) network
	ProviderNetwork string
	// DNSList list of DNS
	DNSList []string
	// UseFloatingIP indicates if floating IP are used (optional)
	UseFloatingIP bool
	// UseLayer3Networking indicates if layer 3 networking features (router) can be used
	// if UseFloatingIP is true UseLayer3Networking must be true
	UseLayer3Networking bool
	// AutoHostNetworkInterfaces indicates if network interfaces are configured automatically by the provider or needs a post configuration
	AutoHostNetworkInterfaces bool
	// VolumeSpeeds map volume types with volume speeds
	VolumeSpeeds map[string]VolumeSpeed.Enum
	// // ObjectStorageType type of Object Storage (ex: swift or s3)
	// ObjectStorageType string
	// MetadataBucket contains the name of the bucket storing metadata
	MetadataBucket string
	DefaultImage   string
}

// Client a AWS provider client
type Client struct {
	Session     *session.Session
	EC2         *ec2.EC2
	Pricing     *pricing.Pricing
	AuthOpts    AuthOpts
	UserDataTpl *template.Template
	//ImageOwners []string

	Cfg      *CfgOptions
}

func (c *Client) CreateGateway(req model.GatewayRequest) (*model.Host, error) {
	return nil, fmt.Errorf("aws.CreateGateway() isn't available by design")
}

func (c *Client) DeleteGateway(string) error {
	return fmt.Errorf("aws.DeleteGateway() isn't available by design")
}

func (c *Client) ListAvailabilityZones(bool) (map[string]bool, error) {
	panic("implement me")
}

func (c *Client) GetNetworkByName(name string) (*model.Network, error) {
	panic("implement me")
}

func (c *Client) GetHostByName(string) (*model.Host, error) {
	panic("implement me")
}

func (c *Client) GetHostState(interface{}) (HostState.Enum, error) {
	panic("implement me")
}

func (c *Client) RebootHost(id string) error {
	panic("implement me")
}

func createFilters() []*ec2.Filter {
	filters := []*ec2.Filter{
		&ec2.Filter{
			Name:   aws.String("state"),
			Values: []*string{aws.String("available")},
		},
		&ec2.Filter{
			Name:   aws.String("architecture"),
			Values: []*string{aws.String("x86_64")},
		},
		&ec2.Filter{
			Name:   aws.String("virtualization-type"),
			Values: []*string{aws.String("hvm")},
		},
		&ec2.Filter{
			Name:   aws.String("root-device-type"),
			Values: []*string{aws.String("ebs")},
		},
	}
	// Ubuntu 099720109477
	// Fedora 013116697141
	// Debian 379101102735
	// CentOS 057448758665
	// CoreOS 595879546273
	// Gentoo 341857463381
	owners := []*string{
		aws.String("099720109477"),
		aws.String("013116697141"),
		aws.String("379101102735"),
		aws.String("057448758665"),
		aws.String("595879546273"),
		aws.String("902460189751"),
	}
	filters = append(filters, &ec2.Filter{
		Name:   aws.String("owner-id"),
		Values: owners,
	})

	return filters
}

// ListImages lists available OS images
func (c *Client) ListImages(all bool) ([]model.Image, error) {

	// TODO Fix this
	// ec2.EC2.WaitUntilBundleTaskComplete(&ec2.DescribeBundleTasksInput{})

	images, err := c.EC2.DescribeImages(&ec2.DescribeImagesInput{
		//Owners: []*string{aws.String("aws-marketplace"), aws.String("self")},
		Filters: createFilters(),
	})
	if err != nil {
		return nil, err
	}
	var list []model.Image
	for _, img := range images.Images {
		if img.Description == nil || strings.Contains(strings.ToUpper(*img.Name), "TEST") {
			continue
		}
		list = append(list, model.Image{
			ID:   *img.ImageId,
			Name: *img.Name,
		})
	}

	return list, nil
}

// Attributes attributes of a compute instance
type Attributes struct {
	ClockSpeed                  string `json:"clockSpeed,omitempty"`
	CurrentGeneration           string `json:"currentGeneration,omitempty"`
	DedicatedEbsThroughput      string `json:"dedicatedEbsThroughput,omitempty"`
	Ecu                         string `json:"ecu,omitempty"`
	EnhancedNetworkingSupported string `json:"enhancedNetworkingSupported,omitempty"`
	InstanceFamily              string `json:"instanceFamily,omitempty"`
	InstanceType                string `json:"instanceType,omitempty"`
	LicenseModel                string `json:"licenseModel,omitempty"`
	Location                    string `json:"location,omitempty"`
	LocationType                string `json:"locationType,omitempty"`
	Memory                      string `json:"memory,omitempty"`
	MetworkPerformance          string `json:"metworkPerformance,omitempty"`
	NormalizationSizeFactor     string `json:"normalizationSizeFactor,omitempty"`
	OperatingSystem             string `json:"operatingSystem,omitempty"`
	Operation                   string `json:"operation,omitempty"`
	PhysicalProcessor           string `json:"physicalProcessor,omitempty"`
	PreInstalledSw              string `json:"preInstalled_sw,omitempty"`
	ProcessorArchitecture       string `json:"processorArchitecture,omitempty"`
	ProcessorFeatures           string `json:"processorFeatures,omitempty"`
	Servicecode                 string `json:"servicecode,omitempty"`
	Servicename                 string `json:"servicename,omitempty"`
	Storage                     string `json:"storage,omitempty"`
	Tenancy                     string `json:"tenancy,omitempty"`
	Usagetype                   string `json:"usagetype,omitempty"`
	Vcpu                        string `json:"vcpu,omitempty"`
}

// Product compute instance product
type Product struct {
	Attributes    Attributes `json:"attributes,omitempty"`
	ProductFamily string     `json:"productFamily,omitempty"`
	Sku           string     `json:"sku,omitempty"`
}

// PriceDimension compute instance price related to term condition
type PriceDimension struct {
	AppliesTo    []string           `json:"appliesTo,omitempty"`
	BeginRange   string             `json:"beginRange,omitempty"`
	Description  string             `json:"description,omitempty"`
	EndRange     string             `json:"endRange,omitempty"`
	PricePerUnit map[string]float32 `json:"pricePerUnit,omitempty"`
	RateCode     string             `json:"RateCode,omitempty"`
	Unit         string             `json:"Unit,omitempty"`
}

// PriceDimensions compute instance price dimensions
type PriceDimensions struct {
	PriceDimensionMap map[string]PriceDimension `json:"price_dimension_map,omitempty"`
}

// TermAttributes compute instance terms
type TermAttributes struct {
	LeaseContractLength string `json:"leaseContractLength,omitempty"`
	OfferingClass       string `json:"offeringClass,omitempty"`
	PurchaseOption      string `json:"purchaseOption,omitempty"`
}

// Card compute instance price card
type Card struct {
	EffectiveDate   string          `json:"effectiveDate,omitempty"`
	OfferTermCode   string          `json:"offerTermCode,omitempty"`
	PriceDimensions PriceDimensions `json:"priceDimensions,omitempty"`
	Sku             string          `json:"sku,omitempty"`
	TermAttributes  TermAttributes  `json:"termAttributes,omitempty"`
}

// OnDemand on demand compute instance cards
type OnDemand struct {
	Cards map[string]Card
}

// Reserved reserved compute instance cards
type Reserved struct {
	Cards map[string]Card `json:"cards,omitempty"`
}

// Terms compute instance prices terms
type Terms struct {
	OnDemand OnDemand `json:"onDemand,omitempty"`
	Reserved Reserved `json:"reserved,omitempty"`
}

// Price Compute instance price information
type Price struct {
	Product         Product `json:"product,omitempty"`
	PublicationDate string  `json:"publicationDate,omitempty"`
	ServiceCode     string  `json:"serviceCode,omitempty"`
	Terms           Terms   `json:"terms,omitempty"`
}

// GetImage returns the Image referenced by id
func (c *Client) GetImage(id string) (*model.Image, error) {
	images, err := c.EC2.DescribeImages(&ec2.DescribeImagesInput{
		ImageIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	if len(images.Images) == 0 {
		return nil, fmt.Errorf("Image %s does not exist", id)
	}
	img := images.Images[0]
	return &model.Image{
		ID:   *img.ImageId,
		Name: *img.Name,
	}, nil
}

// GetTemplate returns the Template referenced by id
func (c *Client) GetTemplate(id string) (*model.HostTemplate, error) {
	input := pricing.GetProductsInput{
		Filters: []*pricing.Filter{
			{
				Field: aws.String("ServiceCode"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("AmazonEC2"),
			},
			{
				Field: aws.String("location"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("US East (Ohio)"),
			},

			{
				Field: aws.String("preInstalledSw"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("NA"),
			},
			{
				Field: aws.String("operatingSystem"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("Linux"),
			},

			{
				Field: aws.String("instanceType"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String(id),
			},
		},
		FormatVersion: aws.String("aws_v1"),
		MaxResults:    aws.Int64(100),
		ServiceCode:   aws.String("AmazonEC2"),
	}

	p, err := c.Pricing.GetProducts(&input)
	if err != nil {
		return nil, err
	}
	for _, price := range p.PriceList {
		jsonPrice, err := json.Marshal(price)
		if err != nil {
			continue
		}
		price := Price{}
		err = json.Unmarshal(jsonPrice, &price)
		if err != nil {
			continue
		}
		if strings.Contains(price.Product.Attributes.Usagetype, "USE2-BoxUsage:") {
			cores, err := strconv.Atoi(price.Product.Attributes.Vcpu)
			if err != nil {
				continue
			}

			tpl := model.HostTemplate{
				HostTemplate: &propsv1.HostTemplate{
					ID:   price.Product.Attributes.InstanceType,
					Name: price.Product.Attributes.InstanceType,
					HostSize: &propsv1.HostSize{
						Cores:    cores,
						DiskSize: int(parseStorage(price.Product.Attributes.Storage)),
						RAMSize:  float32(parseMemory(price.Product.Attributes.Memory)),
					},
				},
			}
			return &tpl, nil
		}
	}
	return nil, fmt.Errorf("Unable to find template %s", id)

}

func parseStorage(str string) float64 {
	r, _ := regexp.Compile("([0-9]*) x ([0-9]*(\\.|,)?[0-9]*) ?([a-z A-Z]*)?")
	b := bytes.Buffer{}
	b.WriteString(str)
	tokens := r.FindAllStringSubmatch(str, -1)
	if len(tokens) <= 0 || len(tokens[0]) <= 1 {
		return 0.0
	}
	factor, err := strconv.ParseFloat(tokens[0][1], 64)
	if err != nil {
		return 0.0
	}
	sizeStr := strings.Replace(tokens[0][2], ",", "", -1)
	size, err := strconv.ParseFloat(sizeStr, 64)
	if err != nil {
		return 0.0
	}
	if size < 10 {
		size = size * 1000
	}
	//	fmt.Println((factor * size))
	return factor * size
}

func parseMemory(str string) float64 {
	r, err := regexp.Compile("([0-9]*(\\.|,)?[0-9]*) ?([a-z A-Z]*)?")
	if err != nil {
		return 0.0
	}
	b := bytes.Buffer{}
	b.WriteString(str)
	tokens := r.FindAllStringSubmatch(str, -1)
	sizeStr := strings.Replace(tokens[0][1], ",", "", -1)
	size, err := strconv.ParseFloat(sizeStr, 64)
	if err != nil {
		return 0.0
	}

	//	fmt.Println((factor * size))
	return size
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (c *Client) ListTemplates(all bool) ([]model.HostTemplate, error) {
	input := pricing.GetProductsInput{
		Filters: []*pricing.Filter{
			{
				Field: aws.String("ServiceCode"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("AmazonEC2"),
			},
			{
				Field: aws.String("location"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("US East (Ohio)"),
			},
			{
				Field: aws.String("preInstalledSw"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("NA"),
			},
			{
				Field: aws.String("operatingSystem"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("Linux"),
			},
		},
		FormatVersion: aws.String("aws_v1"),
		MaxResults:    aws.Int64(100),
		ServiceCode:   aws.String("AmazonEC2"),
	}
	tpls := []model.HostTemplate{}
	//prices := map[string]interface{}{}
	err := c.Pricing.GetProductsPages(&input,
		func(p *pricing.GetProductsOutput, lastPage bool) bool {

			for _, price := range p.PriceList {
				jsonPrice, err := json.Marshal(price)
				if err != nil {
					continue
				}
				price := Price{}
				err = json.Unmarshal(jsonPrice, &price)
				if err != nil {
					continue
				}
				if strings.Contains(price.Product.Attributes.Usagetype, "USE2-BoxUsage:") {
					cores, err := strconv.Atoi(price.Product.Attributes.Vcpu)
					if err != nil {
						continue
					}

					tpl := model.HostTemplate{
						HostTemplate: &propsv1.HostTemplate{
							ID:   price.Product.Attributes.InstanceType,
							Name: price.Product.Attributes.InstanceType,
							HostSize: &propsv1.HostSize{
								Cores:    cores,
								DiskSize: int(parseStorage(price.Product.Attributes.Storage)),
								RAMSize:  float32(parseMemory(price.Product.Attributes.Memory)),
							},
						},
					}
					tpls = append(tpls, tpl)
				}
			}
			return lastPage
		})
	if err != nil {
		return nil, err
	}
	return tpls, nil
}

// CreateKeyPair creates and import a key pair
func (c *Client) CreateKeyPair(name string) (*model.KeyPair, error) {
	publicKey, privateKey, err := system.CreateKeyPair()
	if err != nil {
		return nil, err
	}
	c.EC2.ImportKeyPair(&ec2.ImportKeyPairInput{
		KeyName:           aws.String(name),
		PublicKeyMaterial: publicKey,
	})
	// out, err := c.EC2.CreateKeyPair(&ec2.CreateKeyPairInput{
	// 	KeyName: aws.String(name),
	// })
	if err != nil {
		return nil, err
	}
	return &model.KeyPair{
		ID:         name,
		Name:       name,
		PrivateKey: string(privateKey),
		PublicKey:  string(publicKey),
	}, nil
}

func pStr(s *string) string {
	if s == nil {
		var s string
		return s
	}
	return *s
}

// GetKeyPair returns the key pair identified by id
func (c *Client) GetKeyPair(id string) (*model.KeyPair, error) {
	out, err := c.EC2.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{
		KeyNames: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	kp := out.KeyPairs[0]
	return &model.KeyPair{
		ID:         pStr(kp.KeyName),
		Name:       pStr(kp.KeyName),
		PrivateKey: "",
		PublicKey:  pStr(kp.KeyFingerprint),
	}, nil
}

// ListKeyPairs lists available key pairs
func (c *Client) ListKeyPairs() ([]model.KeyPair, error) {
	out, err := c.EC2.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{})
	if err != nil {
		return nil, err
	}
	keys := []model.KeyPair{}
	for _, kp := range out.KeyPairs {
		keys = append(keys, model.KeyPair{
			ID:         pStr(kp.KeyName),
			Name:       pStr(kp.KeyName),
			PrivateKey: "",
			PublicKey:  pStr(kp.KeyFingerprint),
		})

	}
	return keys, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (c *Client) DeleteKeyPair(id string) error {
	_, err := c.EC2.DeleteKeyPair(&ec2.DeleteKeyPairInput{
		KeyName: aws.String(id),
	})
	return err
}

func (c *Client) saveNetwork(n model.Network) error {
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	buffer := bytes.NewReader(b)
	return c.PutObject("gpac.aws.networks", model.Object{
		Name:    n.ID,
		Content: buffer,
	})
}

func (c *Client) getNetwork(netID string) (*model.Network, error) {
	o, err := c.GetObject("gpac.aws.networks", netID, nil)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.ReadFrom(o.Content)
	net := model.Network{}
	err = json.Unmarshal(buffer.Bytes(), &net)
	if err != nil {
		return nil, err
	}
	return &net, err
}
func (c *Client) removeNetwork(netID string) error {
	return c.DeleteObject("gpac.aws.networks", netID)
}

// CreateNetwork creates a network
func (c *Client) CreateNetwork(req model.NetworkRequest) (*model.Network, error) {
	// m, err := metadata.LoadNetwork(c, req.Name)
	// if err != nil {
	// 	return nil, err
	// }
	// if m != nil {
	// 	return nil, fmt.Errorf("A network already exists with name '%s'", req.Name)
	// }

	vpcOut, err := c.EC2.CreateVpc(&ec2.CreateVpcInput{
		CidrBlock: aws.String(req.CIDR),
	})
	if err != nil {
		return nil, err
	}
	sn, err := c.EC2.CreateSubnet(&ec2.CreateSubnetInput{
		CidrBlock: aws.String(req.CIDR),
		VpcId:     vpcOut.Vpc.VpcId,
	})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	gw, err := c.EC2.CreateInternetGateway(&ec2.CreateInternetGatewayInput{})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	_, err = c.EC2.AttachInternetGateway(&ec2.AttachInternetGatewayInput{
		VpcId:             vpcOut.Vpc.VpcId,
		InternetGatewayId: gw.InternetGateway.InternetGatewayId,
	})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	table, err := c.EC2.DescribeRouteTables(&ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name: aws.String("vpc-id"),
				Values: []*string{
					vpcOut.Vpc.VpcId,
				},
			},
		},
	})
	if err != nil || len(table.RouteTables) < 1 {
		return nil, err
	}

	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	_, err = c.EC2.CreateRoute(&ec2.CreateRouteInput{
		DestinationCidrBlock: aws.String("0.0.0.0/0"),
		GatewayId:            gw.InternetGateway.InternetGatewayId,
		RouteTableId:         table.RouteTables[0].RouteTableId,
	})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	_, err = c.EC2.AssociateRouteTable(&ec2.AssociateRouteTableInput{
		RouteTableId: table.RouteTables[0].RouteTableId,
		SubnetId:     sn.Subnet.SubnetId,
	})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}


	// TODO Fix this
	host, err := c.CreateHost(model.HostRequest{})
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, wrapError("Error creating network", err)
	}
	net := model.Network{
		CIDR:      pStr(vpcOut.Vpc.CidrBlock),
		ID:        pStr(vpcOut.Vpc.VpcId),
		Name:      req.Name,
		IPVersion: req.IPVersion,
		GatewayID: host.ID,
	}
	err = c.saveNetwork(net)
	if err != nil {
		c.DeleteNetwork(*vpcOut.Vpc.VpcId)
		return nil, err
	}
	return &net, nil
}

// GetNetwork returns the network identified by id
func (c *Client) GetNetwork(id string) (*model.Network, error) {
	net, err := c.getNetwork(id)
	if err != nil {
		return nil, err
	}

	out, err := c.EC2.DescribeVpcs(&ec2.DescribeVpcsInput{
		VpcIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	net.CIDR = *out.Vpcs[0].CidrBlock
	net.ID = *out.Vpcs[0].VpcId
	return net, nil
}

// ListNetworks lists available networks
func (c *Client) ListNetworks() ([]*model.Network, error) {
	out, err := c.EC2.DescribeVpcs(&ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}
	nets := []*model.Network{}
	for _, vpc := range out.Vpcs {
		net, err := c.getNetwork(*vpc.VpcId)
		if err != nil {
			return nil, err
		}
		net.CIDR = *vpc.CidrBlock
		net.CIDR = *vpc.VpcId
		nets = append(nets, net)
	}
	return nets, nil

}

// DeleteNetwork deletes the network identified by id
func (c *Client) DeleteNetwork(id string) error {
	net, err := c.getNetwork(id)
	if err == nil {
		c.DeleteHost(net.GatewayID)
		addrs, _ := c.EC2.DescribeAddresses(&ec2.DescribeAddressesInput{
			Filters: []*ec2.Filter{
				{
					Name: aws.String("domain"),
					Values: []*string{
						aws.String("vpc"),
					},
				},
				{
					Name: aws.String("instance-id"),
					Values: []*string{
						aws.String(net.GatewayID),
					},
				},
			},
		})
		for _, addr := range addrs.Addresses {
			c.EC2.DisassociateAddress(&ec2.DisassociateAddressInput{
				AssociationId: addr.AssociationId,
			})
			c.EC2.ReleaseAddress(&ec2.ReleaseAddressInput{
				AllocationId: addr.AllocationId,
			})
		}
	}

	_, err = c.EC2.DeleteVpc(&ec2.DeleteVpcInput{
		VpcId: aws.String(id),
	})
	return err
}

func (c *Client) getSubnets(vpcIDs []string) ([]*ec2.Subnet, error) {
	filters := []*ec2.Filter{}
	for _, id := range vpcIDs {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String("vpc-id"),
			Values: []*string{&id},
		})
	}
	out, err := c.EC2.DescribeSubnets(&ec2.DescribeSubnetsInput{
		Filters: filters,
	})
	if err != nil {
		return nil, err
	}
	return out.Subnets, nil

}
func getState(state *ec2.InstanceState) (HostState.Enum, error) {
	// The low byte represents the state. The high byte is an opaque internal value
	// and should be ignored.
	//
	//    * 0 : pending
	//
	//    * 16 : running
	//
	//    * 32 : shutting-down
	//
	//    * 48 : terminated
	//
	//    * 64 : stopping
	//
	//    * 80 : stopped
	fmt.Println("State", state.Code)
	if state == nil {
		return HostState.ERROR, fmt.Errorf("unexpected host state")
	}
	if *state.Code == 0 {
		return HostState.STARTING, nil
	}
	if *state.Code == 16 {
		return HostState.STARTED, nil
	}
	if *state.Code == 32 {
		return HostState.STOPPING, nil
	}
	if *state.Code == 48 {
		return HostState.STOPPED, nil
	}
	if *state.Code == 64 {
		return HostState.STOPPING, nil
	}
	if *state.Code == 80 {
		return HostState.STOPPED, nil
	}
	return HostState.ERROR, fmt.Errorf("unexpected host state")
}

// Data structure to apply to userdata.sh template
type userData struct {
	//Name of the default user (api.DefaultUser)
	User string
	//Private key used to create the host
	Key string
	//If true activate IP frowarding
	IsGateway bool
	//If true configure default gateway
	AddGateway bool
	//Content of the /etc/resolv.conf of the Gateway
	//Used only if IsGateway is true
	ResolvConf string
	//IP of the gateway
	GatewayIP string
}

func (c *Client) prepareUserData(request model.HostRequest, kp *model.KeyPair, gw *model.Host) (string, error) {
	dataBuffer := bytes.NewBufferString("")
	var ResolvConf string
	var err error
	// if !request.PublicIP {
	// 	var buffer bytes.Buffer
	// 	for _, dns := range client.Cfg.DNSList {
	// 		buffer.WriteString(fmt.Sprintf("nameserver %s\n", dns))
	// 	}
	// 	ResoleConf = buffer.String()
	// }
	ip := ""
	if gw != nil {
		hpNetworkV1 := propsv1.NewHostNetwork()
		err := gw.Properties.Get(HostProperty.NetworkV1, hpNetworkV1)
		if err != nil {
			return "", err
		}
		ip = hpNetworkV1.IPv4Addresses[hpNetworkV1.DefaultNetworkID]
		if ip == "" {
			ip = hpNetworkV1.IPv6Addresses[hpNetworkV1.DefaultNetworkID]
		}
	}

	data := userData{
		User:       model.DefaultUser,
		Key:        strings.Trim(kp.PublicKey, "\n"),
		IsGateway:  request.DefaultGateway == nil && request.Networks[0].Name != model.SingleHostNetworkName, // FIX it later
		AddGateway: !request.PublicIP,
		ResolvConf: ResolvConf,
		GatewayIP:  ip,
	}
	err = c.UserDataTpl.Execute(dataBuffer, data)
	if err != nil {
		return "", err
	}
	encBuffer := bytes.Buffer{}
	enc := base64.NewEncoder(base64.StdEncoding, &encBuffer)
	enc.Write(dataBuffer.Bytes())
	return encBuffer.String(), nil
}

func (c *Client) saveHost(host model.Host) error {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(host)
	if err != nil {
		return err
	}
	return c.PutObject("gpac.aws.wms", model.Object{
		Name:    host.ID,
		Content: bytes.NewReader(buffer.Bytes()),
	})
}
func (c *Client) removeHost(hostID string) error {
	return c.DeleteObject("gpac.aws.wms", hostID)
}
func (c *Client) readHost(hostID string) (*model.Host, error) {
	o, err := c.GetObject("gpac.aws.wms", hostID, nil)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.ReadFrom(o.Content)
	enc := gob.NewDecoder(&buffer)
	var host model.Host
	err = enc.Decode(&host)
	if err != nil {
		return nil, err
	}
	return &host, nil
}

func (c *Client) createSecurityGroup(vpcID string, name string) (string, error) {
	out, err := c.EC2.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		GroupName: aws.String(name),
		VpcId:     aws.String(vpcID),
	})
	if err != nil {
		return "", err
	}
	_, err = c.EC2.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
		IpPermissions: []*ec2.IpPermission{
			&ec2.IpPermission{
				IpProtocol: aws.String("-1"),
			},
		},
	})
	if err != nil {
		return "", err
	}

	_, err = c.EC2.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		IpPermissions: []*ec2.IpPermission{
			&ec2.IpPermission{
				IpProtocol: aws.String("-1"),
			},
		},
	})
	if err != nil {
		return "", err
	}
	return *out.GroupId, nil
}

// CreateHost creates an host that fulfils the request
func (c *Client) CreateHost(request model.HostRequest) (*model.Host, error) {
	// If no KeyPair is supplied a temporay one is created
	kp := request.KeyPair
	if kp == nil {
		kpTmp, err := c.CreateKeyPair(request.ResourceName)
		if err != nil {
			return nil, err
		}
		kp = kpTmp
	}
	// If the host is not a Gateway, get gateway of the first network
	gwID := ""
	var gw *model.Host


	isGateway := request.DefaultGateway == nil && request.Networks[0].Name != model.SingleHostNetworkName // FIX it later

	if !isGateway {
		net, err := c.getNetwork(request.Networks[0].ID)
		if err != nil {
			return nil, err
		}
		gwID = net.GatewayID
		gw, err = c.GetHost(gwID)
		if err != nil {
			return nil, err
		}

	}

	var nets []string
	for _, netid := range(request.Networks) {
		nets = append(nets, netid.ID)
	}

	//get subnet of each network
	sns, err := c.getSubnets(nets)

	//Prepare user data
	userData, err := c.prepareUserData(request, kp, gw)
	if err != nil {
		return nil, err
	}

	//Create networks interfaces
	networkInterfaces := []*ec2.InstanceNetworkInterfaceSpecification{}

	vpcs := map[string][]*ec2.Subnet{}
	for _, sn := range sns {
		vpcs[*sn.VpcId] = append(vpcs[*sn.VpcId], sn)

	}

	i := 0
	for _, netID := range nets {
		if len(vpcs[netID]) < 1 {
			continue
		}
		sn := vpcs[netID][0]
		networkInterfaces = append(networkInterfaces, &ec2.InstanceNetworkInterfaceSpecification{
			SubnetId:                 sn.SubnetId,
			AssociatePublicIpAddress: aws.Bool(false),
			DeleteOnTermination:      aws.Bool(true),
			DeviceIndex:              aws.Int64(int64(i)),
		})
		i++
	}

	//Run instance
	out, err := c.EC2.RunInstances(&ec2.RunInstancesInput{
		ImageId:           aws.String(request.ImageID),
		KeyName:           aws.String(kp.Name),
		InstanceType:      aws.String(request.TemplateID),
		NetworkInterfaces: networkInterfaces,
		MaxCount:          aws.Int64(1),
		MinCount:          aws.Int64(1),
		UserData:          aws.String(userData),
		// TagSpecifications: []*ec2.TagSpecification{
		// 	{
		// 		Tags: []*ec2.Tag{
		// 			{
		// 				Key:   aws.String("Name"),
		// 				Value: aws.String(request.Name),
		// 			},
		// 		},
		// 	},
		// },
	})
	if err != nil {
		return nil, err
	}
	instance := out.Instances[0]

	netIFs, err := c.EC2.DescribeNetworkInterfaces(&ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("attachment.instance-id"),
				Values: []*string{instance.InstanceId},
			},
			&ec2.Filter{
				Name:   aws.String("attachment.device-index"),
				Values: []*string{aws.String(fmt.Sprintf("%d", 0))},
			},
		},
	})
	if err != nil {
		c.DeleteHost(*instance.InstanceId)
		return nil, err
	}

	addr, err := c.EC2.AllocateAddress(&ec2.AllocateAddressInput{
		Domain: aws.String("vpc"),
	})
	if err != nil {
		c.DeleteHost(*instance.InstanceId)
		return nil, err
	}
	//Wait that host is started
	service := providers.Service{
		ClientAPI: c,
	}
	err = service.WaitHostState(*instance.InstanceId, HostState.STARTED, 120*time.Second)
	if err != nil {
		return nil, err
	}
	_, err = c.EC2.AssociateAddress(&ec2.AssociateAddressInput{
		NetworkInterfaceId: netIFs.NetworkInterfaces[0].NetworkInterfaceId,
		AllocationId:       addr.AllocationId,
	})
	if err != nil {
		c.DeleteHost(*instance.InstanceId)
		return nil, err
	}
	//Create api.Host

	_, err = c.GetTemplate(*instance.InstanceType)
	if err != nil {
		c.DeleteHost(*instance.InstanceId)
		return nil, err
	}
	v4IPs := []string{}
	for _, nif := range instance.NetworkInterfaces {
		v4IPs = append(v4IPs, *nif.PrivateIpAddress)
	}

	state, err := getState(instance.State)
	if err != nil {
		c.DeleteHost(*instance.InstanceId)
		return nil, err
	}

	host := model.Host{
		ID:           pStr(instance.InstanceId),
		Name:         request.HostName,
		PrivateKey:   kp.PrivateKey,
		LastState:    state,
	}
	c.saveHost(host)
	return &host, nil
}

// GetHost returns the host identified by id
func (c *Client) GetHost(hostParam interface{}) (*model.Host, error) {
	var (
		host *model.Host
	)

	switch hostParam.(type) {
	case string:
		host := model.NewHost()
		host.ID = hostParam.(string)
	case *model.Host:
		host = hostParam.(*model.Host)
	default:
		panic("hostParam must be a string or a *model.Host!")
	}

	out, err := c.EC2.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(host.ID)},
	})
	if err != nil {
		return nil, err
	}
	instance := out.Reservations[0].Instances[0]
	host, err = c.readHost(host.ID)
	if err != nil {
		host = &model.Host{
			ID: *instance.InstanceId,
		}
	}

	host.LastState, err = getState(instance.State)
	if err != nil {
		return nil, err
	}
	_, err = c.GetTemplate(*instance.InstanceType)
	if err != nil {
		return nil, err
	}
	v4IPs := []string{}
	for _, nif := range instance.NetworkInterfaces {
		v4IPs = append(v4IPs, *nif.PrivateIpAddress)
	}

	return host, nil
}

// ListHosts lists available hosts
func (c *Client) ListHosts() ([]*model.Host, error) {
	panic("Not Implemented")
}

// DeleteHost deletes the host identified by id
func (c *Client) DeleteHost(id string) error {
	c.removeHost(id)
	ips, err := c.EC2.DescribeAddresses(&ec2.DescribeAddressesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("instance-id"),
				Values: []*string{aws.String(id)},
			},
		},
	})
	if err != nil {
		for _, ip := range ips.Addresses {
			c.EC2.ReleaseAddress(&ec2.ReleaseAddressInput{
				AllocationId: ip.AllocationId,
			})
		}
	}
	_, err = c.EC2.TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{aws.String(id)},
	})
	return err

}

// StopHost stops the host identified by id
func (c *Client) StopHost(id string) error {
	_, err := c.EC2.StopInstances(&ec2.StopInstancesInput{
		Force:       aws.Bool(true),
		InstanceIds: []*string{aws.String(id)},
	})
	return err
}

// StartHost starts the host identified by id
func (c *Client) StartHost(id string) error {
	_, err := c.EC2.StartInstances(&ec2.StartInstancesInput{
		InstanceIds: []*string{aws.String(id)},
	})
	return err
}

// //GetSSHConfig creates SSHConfig from host
// func (c *Client) GetSSHConfig(param interface{}) (*system.SSHConfig, error) {
// 	var host *model.Host
// 	switch param.(type) {
// 	case string:
// 		mh, err := metadata.LoadHost(c, param.(string))
// 		if err != nil {
// 			return nil, err
// 		}
// 		host := mh.Get()
// 	case *model.Host:
// 		host := param.(*model.Host)
// 	}

// 	ip := host.GetAccessIP()
// 	sshConfig := system.SSHConfig{
// 		PrivateKey: host.PrivateKey,
// 		Port:       22,
// 		Host:       ip,
// 		User:       api.DefaultUser,
// 	}
// 	if host.GatewayID != "" {
// 		gw, err := c.GetHost(host.GatewayID)
// 		if err != nil {
// 			return nil, err
// 		}
// 		ip := gw.GetAccessIP()
// 		GatewayConfig := system.SSHConfig{
// 			PrivateKey: gw.PrivateKey,
// 			Port:       22,
// 			User:       api.DefaultUser,
// 			Host:       ip,
// 		}
// 		sshConfig.GatewayConfig = &GatewayConfig
// 	}

// 	return &sshConfig, nil
// }

func toVolumeType(speed VolumeSpeed.Enum) string {
	switch speed {
	case VolumeSpeed.COLD:
		return "sc1"
	case VolumeSpeed.HDD:
		return "st1"
	case VolumeSpeed.SSD:
		return "gp2"
	}
	return "st1"
}

func toVolumeSpeed(t *string) VolumeSpeed.Enum {
	if t == nil {
		return VolumeSpeed.HDD
	}
	if *t == "sc1" {
		return VolumeSpeed.COLD
	}
	if *t == "st1" {
		return VolumeSpeed.HDD
	}
	if *t == "gp2" {
		return VolumeSpeed.SSD
	}
	return VolumeSpeed.HDD
}

func toVolumeState(s *string) VolumeState.Enum {
	// VolumeStateCreating = "creating"
	// VolumeStateAvailable = "available"
	// VolumeStateInUse = "in-use"
	// VolumeStateDeleting = "deleting"
	// VolumeStateDeleted = "deleted"
	// VolumeStateError = "error"
	if s == nil {
		return VolumeState.ERROR
	}
	if *s == "creating" {
		return VolumeState.CREATING
	}
	if *s == "available" {
		return VolumeState.AVAILABLE
	}
	if *s == "in-use" {
		return VolumeState.USED
	}
	if *s == "deleting" {
		return VolumeState.DELETING
	}
	if *s == "deleted" {
		return VolumeState.DELETING
	}
	if *s == "error" {
		return VolumeState.ERROR
	}
	return VolumeState.OTHER
}

func (c *Client) saveVolumeName(id, name string) error {
	return c.PutObject("gpac.aws.volumes", model.Object{
		Name:    id,
		Content: strings.NewReader(name),
	})
}

func (c *Client) getVolumeName(id string) (string, error) {
	obj, err := c.GetObject("gpac.aws.volumes", id, nil)
	if err != nil {
		return "", err
	}
	buffer := bytes.Buffer{}
	buffer.ReadFrom(obj.Content)
	return buffer.String(), nil
}

func (c *Client) removeVolumeName(id string) error {
	return c.DeleteObject("gpac.aws.volumes", id)
}

// CreateVolume creates a block volume
//- name is the name of the volume
//- size is the size of the volume in GB
//- volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (c *Client) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	// Check if a volume already exists with the same name
	_volume, err := c.GetVolume(request.Name)
	if err != nil {
		return nil, err
	}
	if _volume != nil {
		return nil, fmt.Errorf("Volume '%s' already exists", request.Name)
	}

	v, err := c.EC2.CreateVolume(&ec2.CreateVolumeInput{
		Size:       aws.Int64(int64(request.Size)),
		VolumeType: aws.String(toVolumeType(request.Speed)),
	})
	if err != nil {
		return nil, err
	}
	err = c.saveVolumeName(*v.VolumeId, request.Name)
	if err != nil {
		c.DeleteVolume(*v.VolumeId)
	}
	volume := model.Volume{
		ID:    pStr(v.VolumeId),
		Name:  request.Name,
		Size:  int(*(v.Size)),
		Speed: toVolumeSpeed(v.VolumeType),
		State: toVolumeState(v.State),
	}
	return &volume, nil
}

// GetVolume returns the volume identified by id
func (c *Client) GetVolume(id string) (*model.Volume, error) {
	out, err := c.EC2.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	v := out.Volumes[0]
	name, err := c.getVolumeName(id)
	if err != nil {
		return nil, err
	}
	volume := model.Volume{
		ID:    pStr(v.VolumeId),
		Name:  name,
		Size:  int(*(v.Size)),
		Speed: toVolumeSpeed(v.VolumeType),
		State: toVolumeState(v.State),
	}
	return &volume, nil
}

// ListVolumes list available volumes
func (c *Client) ListVolumes() ([]model.Volume, error) {
	out, err := c.EC2.DescribeVolumes(&ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}
	volumes := []model.Volume{}
	for _, v := range out.Volumes {
		name, err := c.getVolumeName(*v.VolumeId)
		if err != nil {
			return nil, err
		}
		volume := model.Volume{
			ID:    pStr(v.VolumeId),
			Name:  name,
			Size:  int(*(v.Size)),
			Speed: toVolumeSpeed(v.VolumeType),
			State: toVolumeState(v.State),
		}
		volumes = append(volumes, volume)
	}

	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (c *Client) DeleteVolume(id string) error {
	_, err := c.EC2.DeleteVolume(&ec2.DeleteVolumeInput{
		VolumeId: aws.String(id),
	})
	return err
}

// func (c *Client) saveVolumeAttachmentName(id, name string) error {
// 	return c.PutObject("__volume_atachements__", api.Object{
// 		Name:    id,
// 		Content: strings.NewReader(name),
// 	})
// }

// func (c *Client) getVolumeAttachmentName(id string) (string, error) {
// 	obj, err := c.GetObject("__volume_atachements__", id, nil)
// 	if err != nil {
// 		return "", err
// 	}
// 	buffer := bytes.Buffer{}
// 	buffer.ReadFrom(obj.Content)
// 	return buffer.String(), nil
// }

// func (c *Client) removeVolumeAttachmentName(id string) error {
// 	return c.DeleteObject("__volume_atachements__", id)
// }

// func vaID(hostID string, volumeID string) string {
// 	return fmt.Sprintf("%s###%s", hostID, volumeID)
// }

// CreateVolumeAttachment attaches a volume to an host
//- name the name of the volume attachment
//- volume the volume to attach
//- host on which the volume is attached
func (c *Client) CreateVolumeAttachment(request model.VolumeAttachmentRequest) (string, error) {
	_, err := c.EC2.AttachVolume(&ec2.AttachVolumeInput{
		InstanceId: aws.String(request.HostID),
		VolumeId:   aws.String(request.VolumeID),
	})
	if err != nil {
		return "", err
	}

	/*
	return &api.VolumeAttachment{
		Device:   pStr(va.Device),
		ID:       pStr(va.VolumeId),
		Name:     request.Name,
		ServerID: pStr(va.InstanceId),
		VolumeID: pStr(va.VolumeId),
	}, nil
	*/

	// TODO Fix this

	return "", nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (c *Client) GetVolumeAttachment(serverID, id string) (*model.VolumeAttachment, error) {
	out, err := c.EC2.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	v := out.Volumes[0]
	for _, va := range v.Attachments {
		if *va.InstanceId == serverID {
			return &model.VolumeAttachment{
				Device:   pStr(va.Device),
				ServerID: pStr(va.InstanceId),
				VolumeID: pStr(va.VolumeId),
			}, nil
		}
	}
	return nil, fmt.Errorf("Volume attachment of volume %s on server %s does not exist", serverID, id)
}

// ListVolumeAttachments lists available volume attachment
func (c *Client) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	out, err := c.EC2.DescribeVolumes(&ec2.DescribeVolumesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("attachment.instance-id"),
				Values: []*string{aws.String(serverID)},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	vas := []model.VolumeAttachment{}
	for _, v := range out.Volumes {
		for _, va := range v.Attachments {
			vas = append(vas, model.VolumeAttachment{
				Device:   pStr(va.Device),
				ServerID: pStr(va.InstanceId),
				VolumeID: pStr(va.VolumeId),
			})
		}
	}
	return vas, nil

}


// DeleteVolumeAttachment deletes the volume attachment identifed by id
func (c *Client) DeleteVolumeAttachment(serverID, id string) error {
	_, err := c.EC2.DetachVolume(&ec2.DetachVolumeInput{
		InstanceId: aws.String(serverID),
		VolumeId:   aws.String(id),
	})
	return err
}

// CreateContainer creates an object container
func (c *Client) CreateContainer(name string) error {
	return s3.CreateContainer(awss3.New(c.Session), name, "")
}

// DeleteContainer deletes an object container
func (c *Client) DeleteContainer(name string) error {
	return s3.DeleteContainer(awss3.New(c.Session), name)
}

// ListContainers list object containers
func (c *Client) ListContainers() ([]string, error) {
	return s3.ListContainers(awss3.New(c.Session))
}

// PutObject put an object into an object container
func (c *Client) PutObject(container string, obj model.Object) error {
	return s3.PutObject(awss3.New(c.Session), container, obj)
}

// UpdateObjectMetadata update an object into  object container
func (c *Client) UpdateObjectMetadata(container string, obj model.Object) error {
	return s3.UpdateObjectMetadata(awss3.New(c.Session), container, obj)
}

// GetObject get  object content from an object container
func (c *Client) GetObject(container string, name string, ranges []model.Range) (*model.Object, error) {
	return s3.GetObject(awss3.New(c.Session), container, name, ranges)
}

// GetObjectMetadata get  object metadata from an object container
func (c *Client) GetObjectMetadata(container string, name string) (*model.Object, error) {
	return s3.GetObjectMetadata(awss3.New(c.Session), container, name)
}

// ListObjects list objects of a container
func (c *Client) ListObjects(container string, filter model.ObjectFilter) ([]string, error) {
	return s3.ListObjects(awss3.New(c.Session), container, filter)
}

// CopyObject copies an object
func (c *Client) CopyObject(containerSrc, objectSrc, objectDst string) error {
	return s3.CopyObject(awss3.New(c.Session), containerSrc, objectSrc, objectDst)
}

// DeleteObject deleta an object from a container
func (c *Client) DeleteObject(container, object string) error {
	return s3.DeleteObject(awss3.New(c.Session), container, object)
}

// GetAuthOpts
func (c *Client) GetAuthOpts() (model.Config, error) {
	cfg := model.ConfigMap{}
	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (c *Client) GetCfgOpts() (model.Config, error) {
	cfg := model.ConfigMap{}

	cfg.Set("DNSList", c.Cfg.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", c.Cfg.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", c.Cfg.UseLayer3Networking)

	return cfg, nil
}
