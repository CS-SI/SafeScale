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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"

	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/openstack"
	"github.com/CS-SI/SafeScale/providers/userdata"
	"github.com/CS-SI/SafeScale/system"
)

// ListAvailabilityZones ...
func (c *Client) ListAvailabilityZones(available bool) (map[string]bool, error) {
	panic("implement me")
}

// GetHostByName ...
func (c *Client) GetHostByName(string) (*model.Host, error) {
	panic("implement me")
}

// GetHostState ...
func (c *Client) GetHostState(interface{}) (HostState.Enum, error) {
	panic("implement me")
}

// RebootHost ...
func (c *Client) RebootHost(id string) error {
	panic("implement me")
}

// ResizeHost ...
func (c *Client) ResizeHost(id string, request model.SizingRequirements) (*model.Host, error) {
	panic("ResizeHost() not implemented")
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

// Attributes of a compute instance
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
				ID:       price.Product.Attributes.InstanceType,
				Name:     price.Product.Attributes.InstanceType,
				Cores:    cores,
				DiskSize: int(parseStorage(price.Product.Attributes.Storage)),
				RAMSize:  float32(parseMemory(price.Product.Attributes.Memory)),
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
						ID:       price.Product.Attributes.InstanceType,
						Name:     price.Product.Attributes.InstanceType,
						Cores:    cores,
						DiskSize: int(parseStorage(price.Product.Attributes.Storage)),
						RAMSize:  float32(parseMemory(price.Product.Attributes.Memory)),
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
	var stateMap = map[uint8]HostState.Enum{
		0:  HostState.STARTING,
		16: HostState.STARTED,
		32: HostState.STOPPING,
		48: HostState.STOPPED,
		64: HostState.STOPPING,
		80: HostState.STOPPED,
	}
	fmt.Println("State", state.Code)
	if state == nil {
		return HostState.ERROR, fmt.Errorf("unexpected host state")
	}
	if v, ok := stateMap[uint8(*state.Code)]; ok {
		return v, nil
	}
	return HostState.ERROR, fmt.Errorf("unexpected host state")
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

	// // If the host is not a Gateway, get gateway of the first network
	// gwID := ""
	// var gw *model.Host
	// // var err error

	// isGateway := request.DefaultGateway == nil && request.Networks[0].Name != model.SingleHostNetworkName // FIX it later
	// if !isGateway {
	// 	gwID = request.Networks[0].GatewayID
	// 	// gw, err = c.GetHost(gwID)
	// 	// if err != nil {
	// 	// 	return nil, err
	// 	// }
	// }

	var nets []string
	for _, netid := range request.Networks {
		nets = append(nets, netid.ID)
		_ = nets
	}

	// get subnet of each network
	sns, err := c.getSubnets(request.Networks)
	if err != nil {
		return nil, err
	}

	// Prepare user data
	userData, err := userdata.Prepare(c, request, kp, request.Networks[0].CIDR)
	if err != nil {
		return nil, err
	}

	// Create networks interfaces
	networkInterfaces := []*ec2.InstanceNetworkInterfaceSpecification{}

	vpcs := map[string][]*ec2.Subnet{}
	for _, sn := range sns {
		vpcs[*sn.VpcId] = append(vpcs[*sn.VpcId], sn)

	}

	i := 0
	for _, net := range request.Networks {
		if len(vpcs[net.ID]) < 1 {
			continue
		}
		sn := vpcs[net.ID][0]
		networkInterfaces = append(networkInterfaces, &ec2.InstanceNetworkInterfaceSpecification{
			SubnetId:                 sn.SubnetId,
			AssociatePublicIpAddress: aws.Bool(false),
			DeleteOnTermination:      aws.Bool(true),
			DeviceIndex:              aws.Int64(int64(i)),
		})
		i++
	}

	// // Loads template data to init host property HostSizingV1 (TODO)
	// tpl, err := c.GetTemplate(request.TemplateID)
	// if err != nil {
	// 	return nil, err
	// }

	// Run instance
	out, err := c.EC2.RunInstances(&ec2.RunInstancesInput{
		ImageId:           aws.String(request.ImageID),
		KeyName:           aws.String(kp.Name),
		InstanceType:      aws.String(request.TemplateID),
		NetworkInterfaces: networkInterfaces,
		MaxCount:          aws.Int64(1),
		MinCount:          aws.Int64(1),
		UserData:          aws.String(string(userData)),
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

	// Starting from here, delete host instance if exit with err
	defer func() {
		if err != nil {
			derr := c.DeleteHost(*instance.InstanceId)
			if derr != nil {
				log.Errorf("failed to delete host: %+v", derr)
			}
		}
	}()

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
		return nil, err
	}

	addr, err := c.EC2.AllocateAddress(&ec2.AllocateAddressInput{
		Domain: aws.String("vpc"),
	})
	if err != nil {
		return nil, err
	}

	_, err = c.EC2.AssociateAddress(&ec2.AssociateAddressInput{
		NetworkInterfaceId: netIFs.NetworkInterfaces[0].NetworkInterfaceId,
		AllocationId:       addr.AllocationId,
	})
	if err != nil {
		return nil, err
	}

	v4IPs := []string{}
	for _, nif := range instance.NetworkInterfaces {
		v4IPs = append(v4IPs, *nif.PrivateIpAddress)
		_ = v4IPs
	}

	state, err := getState(instance.State)
	if err != nil {
		return nil, err
	}

	// Create model.Host
	host := model.NewHost()
	host.ID = pStr(instance.InstanceId)
	host.Name = request.ResourceName
	host.PrivateKey = kp.PrivateKey
	host.LastState = state

	// Wait that host is ready, not just that the build is started
	host, err = c.WaitHostReady(host, time.Minute*5)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotAvailable:
			return nil, fmt.Errorf("host '%s' is in ERROR state", request.ResourceName)
		default:
			return nil, fmt.Errorf("timeout waiting host '%s' becoming ready: %s", request.ResourceName, openstack.ProviderErrorToString(err))
		}
	}

	return host, nil
}

// WaitHostReady waits until the host reaches the READY state or timeout
func (c *Client) WaitHostReady(host *model.Host, timeout time.Duration) (*model.Host, error) {
	panic("WaitHostReady() not implemented!")
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
	host = model.NewHost()
	host.ID = *instance.InstanceId

	host, err = c.complementHost(host)
	if err != nil {
		return nil, err
	}

	// host.LastState, err = getState(instance.State)
	// if err != nil {
	// 	return nil, err
	// }

	// tpl, err := c.GetTemplate(*instance.InstanceType)
	// if err != nil {
	// 	return nil, err
	// }
	// v4IPs := []string{}
	// for _, nif := range instance.NetworkInterfaces {
	// 	v4IPs = append(v4IPs, *nif.PrivateIpAddress)
	// }

	return host, nil
}

func (c *Client) complementHost(hostParam interface{}) (*model.Host, error) {
	panic("complementHost() not implemented!")
}

// ListHosts lists available hosts
func (c *Client) ListHosts() ([]*model.Host, error) {
	panic("ListHosts() not Implemented!")
}

// DeleteHost deletes the host identified by id
func (c *Client) DeleteHost(id string) error {
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
