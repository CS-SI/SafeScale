/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ssm"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
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
	return nil
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
func (s stack) GetRawConfigurationOptions(context.Context) (stacks.ConfigurationOptions, fail.Error) {
	if valid.IsNil(s) {
		return stacks.ConfigurationOptions{}, fail.InvalidInstanceError()
	}
	return *s.Config, nil
}

// GetRawAuthenticationOptions ...
func (s stack) GetRawAuthenticationOptions(context.Context) (stacks.AuthenticationOptions, fail.Error) {
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

func (s *stack) UpdateTags(ctx context.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	tags := []*ec2.Tag{}
	for k, v := range lmap {
		tags = append(tags, &ec2.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		})
	}

	xerr := s.rpcCreateTags(ctx, []*string{&id}, tags)
	return xerr
}

func (s *stack) ListTags(ctx context.Context, kind abstract.Enum, id string) (map[string]string, fail.Error) {
	panic("implement me")
}

func (s *stack) DeleteTags(ctx context.Context, kind abstract.Enum, id string, keys []string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	tags := []*ec2.Tag{}
	for _, k := range keys {
		tags = append(tags, &ec2.Tag{
			Key:   aws.String(k),
			Value: nil,
		})
	}

	xerr := s.rpcDeleteTags(ctx, []*string{&id}, tags)
	return xerr
}
