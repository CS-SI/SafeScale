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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or provideried.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package aws

import (
	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/providers"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/stacks/aws"
)

// provider is the providerementation of AWS provider
type provider struct {
	*aws.Stack
}

// Build build a new Client from configuration parameter
func (p *Aws) Build(params map[string]interface{}) (providers.Provider, error) {
	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})

	accessKeyID, _ := identity["AccessKeyID"].(string)
	secretAccessKey, _ := identity["SecretAccessKey"].(string)
	region, _ := compute["Region"].(string)

	authOptions = &stack.AuthenticationOptions{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Region:          region,
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("aws", region, accessKeyID, "0")
	if err != nil {
		return nil, err
	}

	cfgOptions = &stack.ConfigurationOptions{
		MetadataBucket: metadataBucketName,
		DefaultImage:   defaultImage,
	}

	stack, err := aws.New(authOptions, cfgOptions)
	if err != nil {
		return nil, err
	}
	err = stack.InitDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}

	return &provider{Stack: stack}, nil
}

// ListTemplates ...
// Value of all has no impact on the result
func (p *provider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates()
	if err != nil {
		return nil, err
	}
	return allTemplates, nil
}

// ListImages ...
// Value of all has no impact on the result
func (p *provider) ListImages(all bool) ([]resources.Image, error) {
	allImages, err := p.Stack.ListImages()
	if err != nil {
		return nil, err
	}
	return allImages, nil
}

// GetAuthOpts ...
func (p *provider) GetAuthOpts() {
	cfg := providers.ConfigMap{}
	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (p *provider) GetCfgOpts() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)

	return cfg, nil
}

// GetName returns the providerName
func (p *provider) GetName() string {
	return "aws"
}

func init() {
	iaas.Register("aws", &provider{})
}
