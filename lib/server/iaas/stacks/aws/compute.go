/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/system"
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
func (s *Stack) ListImages(all bool) ([]resources.Image, error) {
	images, err := s.EC2.DescribeImages(&ec2.DescribeImagesInput{
		//Owners: []*string{aws.String("aws-marketplace"), aws.String("self")},
		Filters: createFilters(),
	})
	if err != nil {
		return nil, err
	}
	var list []resources.Image
	for _, img := range images.Images {
		if img.Description == nil || strings.Contains(strings.ToUpper(*img.Name), "TEST") {
			continue
		}
		list = append(list, resources.Image{
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


func (s *Stack) ListAvailabilityZones(bool) (map[string]bool, error) {
	panic("implement me")
}


func (s *Stack) GetNetworkByName(name string) (*resources.Network, error) {
	panic("implement me")
}


func (s *Stack) GetHostByName(string) (*resources.Host, error) {
	panic("implement me")
}

func (s *Stack) GetHostState(interface{}) (HostState.Enum, error) {
	panic("implement me")
}


func (s *Stack) RebootHost(id string) error {
	panic("implement me")
}

func (s *Stack) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	panic("implement me")
}


// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (*resources.Image, error) {
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
	return &resources.Image{
		ID:   *img.ImageId,
		Name: *img.Name,
	}, nil
}

// GetTemplate returns the Template referenced by id
func (s *Stack) GetTemplate(id string) (*resources.HostTemplate, error) {
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

			tpl := resources.HostTemplate{
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
//Host templates are sorted using Dominant Resource Fairness Algorithm
func (s *Stack) ListTemplates(all bool) ([]resources.HostTemplate, error) {
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
	tpls := []resources.HostTemplate{}
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

					tpl := resources.HostTemplate{
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
func (s *Stack) CreateKeyPair(name string) (*resources.KeyPair, error) {
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
	return &resources.KeyPair{
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
func (s *Stack) GetKeyPair(id string) (*resources.KeyPair, error) {
	out, err := s.EC2.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{
		KeyNames: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, err
	}
	kp := out.KeyPairs[0]
	return &resources.KeyPair{
		ID:         pStr(kp.KeyName),
		Name:       pStr(kp.KeyName),
		PrivateKey: "",
		PublicKey:  pStr(kp.KeyFingerprint),
	}, nil
}

// ListKeyPairs lists available key pairs
func (s *Stack) ListKeyPairs() ([]resources.KeyPair, error) {
	out, err := s.EC2.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{})
	if err != nil {
		return nil, err
	}
	keys := []resources.KeyPair{}
	for _, kp := range out.KeyPairs {
		keys = append(keys, resources.KeyPair{
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
func (s *Stack) CreateHost(request resources.HostRequest) (*resources.Host, error) {
	panic("implement me")
}

// GetHost returns the host identified by id
func (s *Stack) InspectHost(id interface{}) (*resources.Host, error) {
	panic("implement me")
}

// ListHosts lists available hosts
func (s *Stack) ListHosts() ([]*resources.Host, error) {
	panic("implement me")
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(id string) error {
	panic("implement me")

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
