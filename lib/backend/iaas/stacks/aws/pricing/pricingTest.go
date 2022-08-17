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

package main

import (
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"

	"github.com/davecgh/go-spew/spew"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/pricing"

	ouraws "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/aws"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
)

func TryConnection(bucketName, key string) fail.Error { // nolint
	s := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials("", "", ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(endpoints.UsEast1RegionID),
	}))

	c := pricing.New(s, &aws.Config{})
	if c == nil {
		return fail.NewError("Failure creating pricing session")
	}
	prods, err := c.GetProducts(&pricing.GetProductsInput{
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
	})
	if err != nil {
		return fail.Wrap(err, "unable to fetch products list")
	}

	hostTemplates := make(map[string]abstract.HostTemplate)

	for _, v := range prods.PriceList {
		_ = v
		price, xerr := ouraws.NewPriceFromJSONValue(nil)
		if xerr != nil {
			continue
		}

		tpl := abstract.HostTemplate{
			ID:        price.Product.Attributes.InstanceType,
			Name:      price.Product.Attributes.InstanceType,
			Cores:     price.GetCores(),
			GPUNumber: price.GetGPUNumber(),
			DiskSize:  int(price.GetDiskSize()),
			RAMSize:   float32(price.GetRAMSize()),
		}

		hostTemplates[price.Product.Attributes.InstanceType] = tpl
	}

	fmt.Print(spew.Sdump(hostTemplates))
	fmt.Print(len(hostTemplates))
	return nil
}
