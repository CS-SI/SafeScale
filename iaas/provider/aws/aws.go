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

//go:generate rice embed-go
import (
	"github.com/CS-SI/SafeScale/iaas/provider/api"
	"github.com/CS-SI/SafeScale/iaas/stack/aws"
)

type Aws struct {
	Opts  *aws.AuthOptions
	Cfg   *aws.CfgOptions
	stack *aws.Stack
}

// Build build a new Client from configuration parameter
func (p *Aws) Build(params map[string]interface{}) (api.Provider, error) {
	AccessKeyID, _ := params["AccessKeyID"].(string)
	SecretAccessKey, _ := params["SecretAccessKey"].(string)
	Region, _ := params["Region"].(string)

	newP := Aws{
		AuthOpts: aws.AuthOpts{
			AccessKeyID:     AccessKeyID,
			SecretAccessKey: SecretAccessKey,
			Region:          Region,
		},
	}
	newP.Stack, err = aws.New(newP.AuthOpts)
	if err != nil {
		return nil, err
	}
	return newP, nil
}
