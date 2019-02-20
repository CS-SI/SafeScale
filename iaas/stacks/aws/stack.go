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

	// log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"

	"github.com/CS-SI/SafeScale/iaas/providers"
	"github.com/CS-SI/SafeScale/iaas/stacks"
)

// Stack implements AWS stack
type Stack struct {
	Session *session.Session
	EC2     *ec2.EC2
	Pricing *pricing.Pricing

	authOpts stacks.AuthenticationOptions
	cfgOpts  stacks.ConfigurationOptions
	//ImageOwners []string
}

// //Config AWS configurations
// type Config struct {
// 	ImageOwners    []string
// 	DefaultNetwork string
// }

// Authenticator ...
type Authenticator struct {
	data *stacks.AuthenticationOptions
}

// Retrieve returns nil if it successfully retrieved the value.
// Error is returned if the value were not obtainable, or empty.
func (o Authenticator) Retrieve() (credentials.Value, error) {
	return credentials.Value{
		AccessKeyID:     o.data.AccessKeyID,
		SecretAccessKey: o.data.SecretAccessKey,
		ProviderName:    "internal",
	}, nil
}

// IsExpired returns if the credentials are no longer valid, and need
// to be retrieved.
func (o Authenticator) IsExpired() bool {
	return false
}

// New authenticates and returns a Stack instance
func New(auth *stacks.AuthenticationOptions, cfg *stacks.ConfigurationOptions) (*Stack, error) {
	authenticator := Authenticator{data: auth}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(opts.Region),
		Credentials: credentials.NewCredentials(authenticator),
	})
	if err != nil {
		return nil, err
	}
	sPricing, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-east-1"),
		Credentials: credentials.NewCredentials(authenticator),
	})
	if err != nil {
		return nil, err
	}

	stack := Stack{
		Session:  sess,
		EC2:      ec2.New(sess),
		Pricing:  pricing.New(sPricing),
		AuthOpts: auth,
		CfgOpts:  cfg,
	}
	//metadata.InitializeContainer(&c)

	return &stack, nil
}

// GetAuthOpts ...
func (s *Stack) GetAuthOpts() {
	return s.authOpts
}

// GetCfgOpts return configuration parameters
func (s *Stack) GetCfgOpts() (providers.Config, error) {
	return s.cfgOpts
}
