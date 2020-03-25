/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ssm"
)

type Stack struct {
	Config      *stacks.ConfigurationOptions
	AuthOptions *stacks.AuthenticationOptions
	AwsConfig   *stacks.AWSConfiguration

	S3Service      *s3.S3
	EC2Service     *ec2.EC2
	SSMService     *ssm.SSM
	PricingService *pricing.Pricing
}

// FIXME Orphan method
func (s *Stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return *s.Config
}

// FIXME Orphan method
func (s *Stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return *s.AuthOptions
}

// FIXME Orphan method
// New Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.AWSConfiguration, cfg stacks.ConfigurationOptions) (*Stack, error) {
	stack := &Stack{
		Config:      &cfg,
		AuthOptions: &auth,
		AwsConfig:   &localCfg,
	}

	// FIXME Validate region against endpoints.UsWest2RegionID // UsWest2RegionID      = "us-west-2"      // US West (Oregon).

	accessKeyID := auth.AccessKeyID
	secretAccessKey := auth.SecretAccessKey

	s := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(localCfg.Region),
		Endpoint:         aws.String(localCfg.S3Endpoint),
	}))

	sec2 := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(localCfg.Region),
		Endpoint:         aws.String(localCfg.Ec2Endpoint),
	}))

	sssm := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(localCfg.Region),
		Endpoint:         aws.String(localCfg.SsmEndpoint),
	}))

	spricing := session.Must(session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
		S3ForcePathStyle: aws.Bool(true),
		Region:           aws.String(endpoints.UsEast1RegionID),
	}))

	stack.S3Service = s3.New(s, &aws.Config{})
	stack.EC2Service = ec2.New(sec2, &aws.Config{})
	stack.SSMService = ssm.New(sssm, &aws.Config{})
	stack.PricingService = pricing.New(spricing, &aws.Config{})

	// FIXME Populate things here

	return stack, nil
}
