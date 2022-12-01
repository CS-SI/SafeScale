/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Attributes attributes of a computing instance
type Attributes struct {
	ClockSpeed                  string `json:"clockSpeed,omitempty"`
	CurrentGeneration           string `json:"currentGeneration,omitempty"`
	DedicatedEbsThroughput      string `json:"dedicatedEbsThroughput,omitempty"`
	Ecu                         string `json:"ecu,omitempty"`
	Gpu                         string `json:"gpu,omitempty"`
	EnhancedNetworkingSupported string `json:"enhancedNetworkingSupported,omitempty"`
	InstanceFamily              string `json:"instanceFamily,omitempty"`
	InstanceType                string `json:"instanceType,omitempty"`
	LicenseModel                string `json:"licenseModel,omitempty"`
	Location                    string `json:"location,omitempty"`
	LocationType                string `json:"locationType,omitempty"`
	Memory                      string `json:"memory,omitempty"`
	NetworkPerformance          string `json:"networkPerformance,omitempty"`
	NormalizationSizeFactor     string `json:"normalizationSizeFactor,omitempty"`
	OperatingSystem             string `json:"operatingSystem,omitempty"`
	Operation                   string `json:"operation,omitempty"`
	PhysicalProcessor           string `json:"physicalProcessor,omitempty"`
	PreInstalledSw              string `json:"preInstalledSw,omitempty"`
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

// Reserved represents compute instance cards
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

// NewPriceFromJSONValue creates a Price instance from the content of an aws.JSONValue
func NewPriceFromJSONValue(in aws.JSONValue) (Price, fail.Error) {
	nullPrice := Price{}
	jsonPrice, err := json.Marshal(in)
	if err != nil {
		return nullPrice, fail.ConvertError(err)
	}
	price := Price{}
	if err = json.Unmarshal(jsonPrice, &price); err != nil {
		return nullPrice, fail.ConvertError(err)
	}
	return price, nil
}

func (p Price) GetCores() int {
	return p.parseInt(p.Product.Attributes.Vcpu, 1)
}

func (p Price) GetGPUNumber() int {
	return p.parseInt(p.Product.Attributes.Gpu, 0)
}

func (p Price) GetRAMSize() float64 {
	return p.parseFloat(p.Product.Attributes.Memory)
}

func (p Price) GetCPUFreq() float64 {
	return p.parseFloat(p.Product.Attributes.ClockSpeed)
}

func (p Price) GetDiskSize() float64 {
	return p.parseStorage(p.Product.Attributes.Storage)
}

// parseMemory ...
func (p Price) parseFloat(str string) float64 {
	r, err := regexp.Compile(`([0-9]*(\\.|,)?[0-9]*) ?([a-z A-Z]*)?`) // nolint
	if err != nil {
		return 0.0
	}

	b := bytes.Buffer{}
	b.WriteString(str)
	tokens := r.FindAllStringSubmatch(str, -1)
	sizeStr := strings.ReplaceAll(tokens[0][1], ",", "")
	size, err := strconv.ParseFloat(sizeStr, 64)
	if err != nil {
		return 0.0
	}

	return size
}

// parseStorage ...
func (p Price) parseStorage(str string) float64 {
	r, err := regexp.Compile(`([0-9]*) x ([0-9]*(\\.|,)?[0-9]*) ?([a-z A-Z]*)?`) // nolint
	if err != nil {
		return 0.0
	}

	b := bytes.Buffer{}
	b.WriteString(str)
	tokens := r.FindAllStringSubmatch(str, -1)
	if len(tokens) == 0 || len(tokens[0]) <= 1 {
		return 0.0
	}
	factor, err := strconv.ParseFloat(tokens[0][1], 64)
	if err != nil {
		return 0.0
	}
	sizeStr := strings.ReplaceAll(tokens[0][2], ",", "")
	size, err := strconv.ParseFloat(sizeStr, 64)
	if err != nil {
		return 0.0
	}
	if size < 10 {
		size *= 1000
	}
	return factor * size
}

// parseNumber ...
func (p Price) parseInt(str string, failureValue int) int {
	okValue, err := strconv.Atoi(str)
	if err != nil {
		return failureValue
	}
	return okValue
}
