/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package main

import (
	"encoding/json"
	"fmt"

	"github.com/CS-SI/SafeScale/lib/utils/fail"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/pricing"
	"github.com/davecgh/go-spew/spew"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"

	ouraws "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/aws"
)

func TryConnection(bucketName, key string) error {
	s := session.Must(
		session.NewSession(
			&aws.Config{
				Credentials:      credentials.NewStaticCredentials("", "", ""),
				S3ForcePathStyle: aws.Bool(true),
				Region:           aws.String(endpoints.UsEast1RegionID),
			},
		),
	)

	c := pricing.New(s, &aws.Config{})
	if c == nil {
		return fail.Errorf("Failure creating pricing session", nil)
	}
	prods, err := c.GetProducts(
		&pricing.GetProductsInput{
			Filters: []*pricing.Filter{
				{
					Field: aws.String("ServiceCode"),
					Type:  aws.String("TERM_MATCH"),
					Value: aws.String("AmazonEC2"),
				},
				{
					Field: aws.String("operatingSystem"),
					Type:  aws.String("TERM_MATCH"),
					Value: aws.String("Linux"),
				},
			},
			MaxResults:  aws.Int64(100),
			ServiceCode: aws.String("AmazonEC2"),
		},
	)
	if err != nil {
		return fail.Wrap(err, "unable to fetch products list")
	}

	hostTemplates := make(map[string]abstract.HostTemplate)

	for _, price := range prods.PriceList {
		jsonPrice, err := json.Marshal(price)
		if err != nil {
			continue
		}
		price := ouraws.Price{}
		err = json.Unmarshal(jsonPrice, &price)
		if err != nil {
			continue
		}

		tpl := abstract.HostTemplate{
			ID:        price.Product.Attributes.InstanceType,
			Name:      price.Product.Attributes.InstanceType,
			Cores:     ouraws.ParseNumber(price.Product.Attributes.Vcpu, 1),
			GPUNumber: ouraws.ParseNumber(price.Product.Attributes.Gpu, 0),
			DiskSize:  int(ouraws.ParseStorage(price.Product.Attributes.Storage)),
			RAMSize:   float32(ouraws.ParseMemory(price.Product.Attributes.Memory)),
		}

		hostTemplates[price.Product.Attributes.InstanceType] = tpl
	}

	fmt.Print(spew.Sdump(hostTemplates))
	fmt.Print(len(hostTemplates))
	return nil
}

func main() {
	err := TryConnection("", "")
	if err != nil {
		fmt.Printf(err.Error())
	}
}
