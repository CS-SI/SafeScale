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

package gcp

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	apiprovider "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/gcp"
)

// provider is the provider implementation of the Gcp provider
type provider struct {
	api.Stack
}

// New creates a new instance of gcp provider
func New() apiprovider.Provider {
	return &provider{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (apiprovider.Provider, error) {
	// tenantName, _ := params["name"].(string)

	identityCfg, ok := params["identity"].(map[string]interface{})
	if !ok {
		return &provider{}, fmt.Errorf("Section identity not found in tenants.toml !!")
	}

	computeCfg, ok := params["compute"].(map[string]interface{})
	if !ok {
		return &provider{}, fmt.Errorf("Section compute not found in tenants.toml !!")
	}

	// network, _ := params["network"].(map[string]interface{})

	projectId, _ := identityCfg["project_id"].(string)
	privateKeyId, _ := identityCfg["private_key_id"].(string)
	privateKey, _ := identityCfg["private_key"].(string)
	clientEmail, _ := identityCfg["client_email"].(string)
	clientId, _ := identityCfg["client_id"].(string)
	authUri, _ := identityCfg["auth_uri"].(string)
	tokenUri, _ := identityCfg["token_uri"].(string)
	authProvider, _ := identityCfg["auth_provider_x509_cert_url"].(string)
	clientCertUrl, _ := identityCfg["client_x509_cert_url"].(string)
	region, _ := computeCfg["Region"].(string)
	zone, _ := computeCfg["Zone"].(string)

	gcpConf := stacks.GCPConfiguration{
		Type: "service_account",
		ProjectId: projectId,
		PrivateKeyId: privateKeyId,
		PrivateKey: privateKey,
		ClientEmail: clientEmail,
		ClientId: clientId,
		AuthUri: authUri,
		TokenUri: tokenUri,
		AuthProvider: authProvider,
		ClientCert: clientCertUrl,
		Region: region,
		Zone: zone,
	}

	username, _ := identityCfg["Username"].(string)
	password, _ := identityCfg["Password"].(string)
	identityEndpoint, _ := identityCfg["auth_uri"].(string)


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
		Region:           region,
		ProjectName:      projectName,
		ProjectID:        projectID,
		FloatingIPPool:   "public",
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("gcp", region, "", projectID)
	if err != nil {
		return nil, err
	}

	cfgOptions := stacks.ConfigurationOptions{
		DNSList:             []string{"8.8.8.8", "1.1.1.1"},
		UseFloatingIP:             true,
		AutoHostNetworkInterfaces: false,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"standard":   VolumeSpeed.COLD,
			"performant": VolumeSpeed.HDD,
		},
		MetadataBucket: metadataBucketName,
		DefaultImage:     defaultImage,
		OperatorUsername: operatorUsername,
		UseNATService: true,
	}

	stack, err := gcp.New(authOptions, gcpConf, cfgOptions)
	if err != nil {
		return nil, err
	}

	nlog := api.NewLoggedStack(stack, "gcp")

	return &provider{nlog}, nil
}

// GetAuthOpts returns the auth options
func (p *provider) GetAuthOpts() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.GetAuthenticationOptions()
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (p *provider) GetCfgOpts() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	return cfg, nil
}

// GetName returns the providerName
func (p *provider) GetName() string {
	return "gcp"
}

func init() {
	iaas.Register("gcp", &provider{})
}
