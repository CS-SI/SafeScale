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

// Package aws contains the implementation of stack for Amazon
package aws

import (
	"fmt"

	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ssm"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
)

type stack struct {
	Config      *stacks.ConfigurationOptions
	AuthOptions *stacks.AuthenticationOptions
	AwsConfig   *stacks.AWSConfiguration

	S3Service      *s3.S3
	EC2Service     *ec2.EC2
	SSMService     *ssm.SSM
	PricingService *pricing.Pricing

	*temporal.MutableTimings
}

// NullStack is not exposed through API, is needed essentially by tests
func NullStack() *stack { // nolint
	return &stack{}
}

// IsNull tells if the instance represents a null value
func (s *stack) IsNull() bool {
	return s == nil || s.EC2Service == nil
}

// GetStackName returns the name of the stack
func (s stack) GetStackName() (string, fail.Error) {
	return "aws", nil
}

// GetRawConfigurationOptions ...
func (s stack) GetRawConfigurationOptions() (stacks.ConfigurationOptions, fail.Error) {
	if valid.IsNil(s) {
		return stacks.ConfigurationOptions{}, fail.InvalidInstanceError()
	}
	return *s.Config, nil
}

// GetRawAuthenticationOptions ...
func (s stack) GetRawAuthenticationOptions() (stacks.AuthenticationOptions, fail.Error) {
	if valid.IsNil(s) {
		return stacks.AuthenticationOptions{}, fail.InvalidInstanceError()
	}
	return *s.AuthOptions, nil
}

// New creates and initializes an AWS stack
func New(auth stacks.AuthenticationOptions, localCfg stacks.AWSConfiguration, cfg stacks.ConfigurationOptions) (*stack, error) { // nolint
	if localCfg.Ec2Endpoint == "" {
		localCfg.Ec2Endpoint = fmt.Sprintf("https://ec2.%s.amazonaws.com", localCfg.Region)
	}
	if localCfg.SsmEndpoint == "" {
		localCfg.SsmEndpoint = fmt.Sprintf("https://ssm.%s.amazonaws.com", localCfg.Region)
	}

	stack := &stack{
		Config:      &cfg,
		AuthOptions: &auth,
		AwsConfig:   &localCfg,
	}

	accessKeyID := auth.AccessKeyID
	secretAccessKey := auth.SecretAccessKey

	ss3 := session.Must(session.NewSession(&aws.Config{
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

	stack.S3Service = s3.New(ss3, &aws.Config{})
	stack.EC2Service = ec2.New(sec2, &aws.Config{})
	stack.SSMService = ssm.New(sssm, &aws.Config{})
	stack.PricingService = pricing.New(spricing, &aws.Config{})

	// Note: If timeouts and/or delays have to be adjusted, do it here in stack.timeouts and/or stack.delays
	if cfg.Timings != nil {
		stack.MutableTimings = cfg.Timings
	} else {
		stack.MutableTimings = temporal.NewTimings()
	}

	return stack, nil
}

// Timings returns the instance containing current timeout/delay settings
func (s *stack) Timings() (temporal.Timings, fail.Error) {
	if s == nil {
		return temporal.NewTimings(), fail.InvalidInstanceError()
	}
	if s.MutableTimings == nil {
		s.MutableTimings = temporal.NewTimings()
	}
	return s.MutableTimings, nil
}
