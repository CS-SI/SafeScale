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
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"

	"github.com/CS-SI/SafeScale/iaas/model"
	"github.com/CS-SI/SafeScale/iaas/model/enums/HostState"
	propsv1 "github.com/CS-SI/SafeScale/iaas/model/properties/v1"
	"github.com/CS-SI/SafeScale/iaas/userdata"
	"github.com/CS-SI/SafeScale/system"
)

func wrapError(msg string, err error) error {
	if err == nil {
		return nil
	}
	if aerr, ok := err.(awserr.Error); ok {
		return fmt.Errorf("%s: cause by %s", msg, aerr.Message())
	}
	return err
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
func (s *Stack) ListImages() ([]model.Image, error) {
	images, err := s.EC2.DescribeImages(&ec2.DescribeImagesInput{
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

//Attributes attributes of a compute instance
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

//Product compute instance product
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

//Terms compute instance prices terms
type Terms struct {
	OnDemand OnDemand `json:"onDemand,omitempty"`
	Reserved Reserved `json:"reserved,omitempty"`
}

//Price Compute instance price information
type Price struct {
	Product         Product `json:"product,omitempty"`
	PublicationDate string  `json:"publicationDate,omitempty"`
	ServiceCode     string  `json:"serviceCode,omitempty"`
	Terms           Terms   `json:"terms,omitempty"`
}

// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (*model.Image, error) {
	images, err := s.EC2.DescribeImages(&ec2.DescribeImagesInput{
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
func (s *Stack) GetTemplate(id string) (*model.HostTemplate, error) {
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

	p, err := s.Pricing.GetProducts(&input)
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
//Host templates are sorted using Dominant Resource Fairness Algorithm
func (s *Stack) ListTemplates(all bool) ([]model.HostTemplate, error) {
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
	err := s.Pricing.GetProductsPages(&input,
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
func (s *Stack) CreateKeyPair(name string) (*model.KeyPair, error) {
	publicKey, privateKey, err := system.CreateKeyPair()
	if err != nil {
		return nil, err
	}
	s.EC2.ImportKeyPair(&ec2.ImportKeyPairInput{
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
func (s *Stack) GetKeyPair(id string) (*model.KeyPair, error) {
	out, err := s.EC2.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{
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
func (s *Stack) ListKeyPairs() ([]model.KeyPair, error) {
	out, err := s.EC2.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{})
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
func (s *Stack) DeleteKeyPair(id string) error {
	_, err := s.EC2.DeleteKeyPair(&ec2.DeleteKeyPairInput{
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

// CreateHost creates an host that fulfils the request
func (s *Stack) CreateHost(request model.HostRequest) (*model.Host, error) {

	// If no KeyPair is supplied a temporay one is created
	kp := request.KeyPair
	if kp == nil {
		kpTmp, err := s.CreateKeyPair(request.ResourceName)
		if err != nil {
			return nil, err
		}
		kp = kpTmp
	}

	// If the host is not a Gateway, get gateway of the first network
	gwID := ""
	var gw *model.Host
	if request.DefaultGateway != nil {
		net, err := s.GetNetwork(request.Networks[0].ID)
		if err != nil {
			return nil, err
		}
		gwID = net.GatewayID
		gw, err = s.GetHost(gwID)
		if err != nil {
			return nil, err
		}
	}

	// get subnet of each network
	sns, err := s.getSubnets(request.Networks)

	//Prepare user data
	userData, err := userdata.Prepare(request, kp, gw)
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
		netID := net.ID
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

	// Run instance
	out, err := s.EC2.RunInstances(&ec2.RunInstancesInput{
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

	defer func() {
		if err != nil {
			derr := s.DeleteHost(*instance.InstanceId)
			if derr != nil {
				log.Debugf("%+v", derr)
			}
		}
	}()

	netIFs, err := s.EC2.DescribeNetworkInterfaces(&ec2.DescribeNetworkInterfacesInput{
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

	addr, err := s.EC2.AllocateAddress(&ec2.AllocateAddressInput{
		Domain: aws.String("vpc"),
	})
	if err != nil {
		s.DeleteHost(*instance.InstanceId)
		return nil, err
	}

	// Wait that host is started
	_, err = s.WaitHostReady(*instance.InstanceId, HostState.STARTED, 120*time.Second)
	if err != nil {
		return nil, err
	}
	_, err = s.EC2.AssociateAddress(&ec2.AssociateAddressInput{
		NetworkInterfaceId: netIFs.NetworkInterfaces[0].NetworkInterfaceId,
		AllocationId:       addr.AllocationId,
	})
	if err != nil {
		return nil, err
	}

	// Create model.Host
	tpl, err := s.GetTemplate(*instance.InstanceType)
	if err != nil {
		return nil, err
	}
	v4IPs := []string{}
	for _, nif := range instance.NetworkInterfaces {
		v4IPs = append(v4IPs, *nif.PrivateIpAddress)
	}
	accessAddr := ""
	if instance.PublicIpAddress != nil {
		accessAddr = *instance.PublicIpAddress
	}
	state, err := getState(instance.State)
	if err != nil {
		return nil, err
	}

	host := model.Host{
		ID:           pStr(instance.InstanceId),
		Name:         request.ResourceName,
		Size:         tpl.HostSize,
		PrivateIPsV4: v4IPs,
		AccessIPv4:   accessAddr,
		PrivateKey:   kp.PrivateKey,
		State:        state,
		GatewayID:    gwID,
	}
	return &host, nil
}

// GetHost returns the host identified by id
func (s *Stack) GetHost(id string) (*model.Host, error) {

	out, err := s.EC2.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	instance := out.Reservations[0].Instances[0]
	host := &model.Host{
		ID: *instance.InstanceId,
	}

	host.LastState, err = getState(instance.State)
	if err != nil {
		return nil, err
	}
	tpl, err := s.GetTemplate(*instance.InstanceType)
	if err != nil {
		return nil, err
	}
	host.Size = tpl.HostSize
	v4IPs := []string{}
	for _, nif := range instance.NetworkInterfaces {
		v4IPs = append(v4IPs, *nif.PrivateIpAddress)
	}
	accessAddr := ""
	if instance.PublicIpAddress != nil {
		accessAddr = *instance.PublicIpAddress
	}
	host.PrivateIPsV4 = v4IPs
	host.AccessIPv4 = accessAddr

	return host, nil
}

// ListHosts lists available hosts
func (s *Stack) ListHosts() ([]model.Host, error) {
	panic("Not Implemented")
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(id string) error {
	s.removeHost(id)
	ips, err := s.EC2.DescribeAddresses(&ec2.DescribeAddressesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("instance-id"),
				Values: []*string{aws.String(id)},
			},
		},
	})
	if err != nil {
		for _, ip := range ips.Addresses {
			s.EC2.ReleaseAddress(&ec2.ReleaseAddressInput{
				AllocationId: ip.AllocationId,
			})
		}
	}
	_, err = s.EC2.TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{aws.String(id)},
	})
	return err

}

// StopHost stops the host identified by id
func (s *Stack) StopHost(id string) error {
	_, err := s.EC2.StopInstances(&ec2.StopInstancesInput{
		Force:       aws.Bool(true),
		InstanceIds: []*string{aws.String(id)},
	})
	return err
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(id string) error {
	_, err := s.EC2.StartInstances(&ec2.StartInstancesInput{
		InstanceIds: []*string{aws.String(id)},
	})
	return err
}
