package main

import (
	"encoding/json"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/pricing"
	"github.com/davecgh/go-spew/spew"

	ouraws "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/aws"
)

func TryConnection(bucketName, key string) {
	s := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials("", "", ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(endpoints.UsEast1RegionID),
	}))

	c := pricing.New(s, &aws.Config{})
	if c == nil {
		panic("Failure")
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
		panic(err)
	}

	hostTemplates := make(map[string]resources.HostTemplate)

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

		tpl := resources.HostTemplate{
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
}

func main() {
	TryConnection("", "")
}
