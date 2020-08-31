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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or provideried.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package aws

import (
    "fmt"

    "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/utils/scerr"

    "github.com/CS-SI/SafeScale/lib/server/iaas"
    "github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
    "github.com/CS-SI/SafeScale/lib/server/iaas/providers"
    apiprovider "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
    "github.com/CS-SI/SafeScale/lib/server/iaas/resources"
    "github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumespeed"
    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/aws"
)

// provider is the provider implementation of the Aws provider
type provider struct {
    *aws.Stack

    tenantParameters map[string]interface{}
}

func (p *provider) AddPublicIPToVIP(ip *resources.VirtualIP) error {
    return scerr.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME Technical debt
}

func (p *provider) BindHostToVIP(*resources.VirtualIP, string) error {
    return scerr.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME Technical debt
}

func (p *provider) UnbindHostFromVIP(*resources.VirtualIP, string) error {
    return scerr.NotImplementedError("UnbindHostFromVIP() not implemented yet") // FIXME Technical debt
}

func (p *provider) DeleteVIP(*resources.VirtualIP) error {
    return scerr.NotImplementedError("DeleteVIP() not implemented yet") // FIXME Technical debt
}

func (p *provider) GetTenantParameters() map[string]interface{} {
    return p.tenantParameters
}

// New creates a new instance of aws provider
func New() apiprovider.Provider {
    return &provider{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (apiprovider.Provider, error) {
    // tenantName, _ := params["name"].(string)

    identityCfg, ok := params["identity"].(map[string]interface{})
    if !ok {
        return &provider{}, fmt.Errorf("section identity not found in tenants.toml")
    }

    computeCfg, ok := params["compute"].(map[string]interface{})
    if !ok {
        return &provider{}, fmt.Errorf("section compute not found in tenants.toml")
    }

    networkName := "safescale"

    networkCfg, ok := params["network"].(map[string]interface{})
    if !ok {
        logrus.Warnf("section network not found in tenants.toml !!")
    } else {
        newNetworkName, _ := networkCfg["ProviderNetwork"].(string)
        if newNetworkName != "" {
            networkName = newNetworkName
        }
    }

    region, ok := computeCfg["Region"].(string)
    if !ok {
        return &provider{}, fmt.Errorf("no compute region found in tenants.toml")
    }
    zone, ok := computeCfg["Zone"].(string)
    if !ok {
        return &provider{}, fmt.Errorf("no compute zone found in tenants.toml")
    }

    s3Endpoint, ok := computeCfg["S3"].(string)
    if !ok {
        return &provider{}, fmt.Errorf("no s3 endpoint found in tenants.toml")
    }
    ec2Endpoint, ok := computeCfg["EC2"].(string)
    if !ok {
        return &provider{}, fmt.Errorf("no ec2 endpoint found in tenants.toml")
    }
    ssmEndpoint, ok := computeCfg["SSM"].(string)
    if !ok {
        return &provider{}, fmt.Errorf("no ssm endpoint found in tenants.toml")
    }

    awsConf := stacks.AWSConfiguration{
        S3Endpoint:  s3Endpoint,
        Ec2Endpoint: ec2Endpoint,
        SsmEndpoint: ssmEndpoint,
        Region:      region,
        Zone:        zone,
        NetworkName: networkName,
    }

    username, ok := identityCfg["Username"].(string)
    if !ok || username == "" {
        username, _ = identityCfg["User"].(string)
    }
    password, _ := identityCfg["Password"].(string)

    accessKeyID, ok := identityCfg["AccessKeyID"].(string)
    if !ok || accessKeyID == "" {
        return &provider{}, fmt.Errorf("no secret key id provided in tenants.toml")
    }

    secretAccessKey, ok := identityCfg["SecretAccessKey"].(string)
    if !ok || secretAccessKey == "" {
        return &provider{}, fmt.Errorf("no secret access key provided in tenants.toml")
    }

    identityEndpoint, ok := identityCfg["auth_uri"].(string)
    if !ok || identityEndpoint == "" {
        return &provider{}, fmt.Errorf("no identity endpoint provided in tenants.toml")
    }

    projectName, _ := computeCfg["ProjectName"].(string)
    projectID, _ := computeCfg["ProjectID"].(string)
    defaultImage, _ := computeCfg["DefaultImage"].(string)

    operatorUsername := resources.DefaultUser
    if operatorUsernameIf, ok := computeCfg["OperatorUsername"]; ok {
        operatorUsername = operatorUsernameIf.(string)
    }

    authOptions := stacks.AuthenticationOptions{
        IdentityEndpoint: identityEndpoint,
        Username:         username,
        Password:         password,
        AccessKeyID:      accessKeyID,
        SecretAccessKey:  secretAccessKey,
        Region:           region,
        ProjectName:      projectName,
        ProjectID:        projectID,
        FloatingIPPool:   "public",
    }

    providerName := "aws"

    metadataBucketName, err := objectstorage.BuildMetadataBucketName(providerName, region, "", projectID)
    if err != nil {
        return nil, err
    }

    cfgOptions := stacks.ConfigurationOptions{
        DNSList:                   []string{},
        UseFloatingIP:             true,
        AutoHostNetworkInterfaces: false,
        VolumeSpeeds: map[string]volumespeed.Enum{
            "standard":   volumespeed.COLD,
            "performant": volumespeed.HDD,
        },
        MetadataBucket:   metadataBucketName,
        DefaultImage:     defaultImage,
        OperatorUsername: operatorUsername,
        UseNATService:    false,
        ProviderName:     providerName,
        BuildSubnetworks: false, // FIXME AWS by default don't build subnetworks
    }

    stack, err := aws.New(authOptions, awsConf, cfgOptions)
    if err != nil {
        return nil, err
    }

    evalid := apiprovider.NewValidatedProvider(&provider{stack, params}, providerName)
    etrace := apiprovider.NewErrorTraceProvider(evalid, providerName)
    prov := apiprovider.NewLoggedProvider(etrace, providerName)

    return prov, nil
}

// GetAuthenticationOptions returns the auth options
func (p *provider) GetAuthenticationOptions() (providers.Config, error) {
    cfg := providers.ConfigMap{}

    opts := p.Stack.GetAuthenticationOptions()
    cfg.Set("TenantName", opts.TenantName)
    cfg.Set("Login", opts.Username)
    cfg.Set("Password", opts.Password)
    cfg.Set("AuthUrl", opts.IdentityEndpoint)
    cfg.Set("Region", opts.Region)
    return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p *provider) GetConfigurationOptions() (providers.Config, error) {
    cfg := providers.ConfigMap{}

    opts := p.Stack.GetConfigurationOptions()
    cfg.Set("DNSList", opts.DNSList)
    cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
    cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
    cfg.Set("DefaultImage", opts.DefaultImage)
    cfg.Set("MetadataBucketName", opts.MetadataBucket)
    cfg.Set("OperatorUsername", opts.OperatorUsername)
    cfg.Set("ProviderName", p.GetName())
    cfg.Set("BuildSubnetworks", opts.BuildSubnetworks)
    return cfg, nil
}

// GetName returns the providerName
func (p *provider) GetName() string {
    return "aws"
}

// ListImages ...
func (p *provider) ListImages(all bool) ([]resources.Image, error) {
    return p.Stack.ListImages()
}

func (p *provider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
    return p.Stack.ListTemplates()
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() providers.Capabilities {
    return providers.Capabilities{
        PrivateVirtualIP: true,
    }
}

func init() {
    iaas.Register("aws", &provider{})
}
