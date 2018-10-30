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

package opentelekom

import (
	"github.com/CS-SI/SafeScale/iaas/stack/huaweicloud"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/enums/VolumeSpeed"
)

const (
	authURL string = "https://iam.%s.otc.t-systems.com"
)

// Client is the implementation of the flexibleengine driver regarding to the api.ClientAPI
type OpenTelekom struct {
	AuthOpts AuthenticationOptions
	CfgOpts  ConfigurationOptions
	stack    *huaweicloud.Stack
}

// Build build a new Client from configuration parameter
func (p *OpenTelekom) Build(params map[string]interface{}) (*OpenTelekom, error) {
	Username, _ := params["Username"].(string)
	Password, _ := params["Password"].(string)
	DomainName, _ := params["DomainName"].(string)
	ProjectID, _ := params["ProjectID"].(string)
	VPCName, _ := params["VPCName"].(string)
	VPCCIDR, _ := params["VPCCIDR"].(string)
	Region, _ := params["Region"].(string)
	IdentityEndpoint, _ := params["IdentityEndpoint"].(string)
	if IdentityEndpoint == "" {
		IdentityEndpoint = fmt.Sprintf(authUrl, Region)
	}
	S3AccessKeyID, _ := params["S3AccessKeyID"].(string)
	S3AccessKeyPassword, _ := params["S3AccessKeyPassword"].(string)

	newP := OpenTelekom{
		AuthOpts: AuthenticationOptions{
			IdentityEndpoint:    IdentityEndpoint,
			Username:            Username,
			Password:            Password,
			DomainName:          DomainName,
			ProjectID:           ProjectID,
			Region:              Region,
			AllowReauth:         true,
			VPCName:             VPCName,
			VPCCIDR:             VPCCIDR,
			IdentityEndpoint:    IdentityEndpoint,
			S3AccessKeyID:       S3AccessKeyID,
			S3AccessKeyPassword: S3AccessKeyPassword,
		},
		CfgOpts: ConfigurationOptions{
			DNSList:             []string{"1.1.1.1"},
			UseFloatingIP:       true,
			UseLayer3Networking: false,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"SATA": VolumeSpeed.COLD,
				"SAS":  VolumeSpeed.HDD,
				"SSD":  VolumeSpeed.SSD,
			},
		},
	}
	newP.stack, err := huaweicloud.New(newP.authOptions, newP.cfgOptions)
	if err != nil {
		return nil, err
	}
	return &newP, nil
}

// init registers the opentelekom provider
func init() {
	providers.Register("opentelekom", &OpenTelekom{})
}
