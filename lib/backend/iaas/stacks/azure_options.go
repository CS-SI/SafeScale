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

package stacks

// AzureConfiguration stores Google cloud platform configuration
type AzureConfiguration struct {
	Type           string `json:"type" validate:"required"`
	ClientID       string `json:"client_id"`
	Region         string `json:"-"`
	Zone           string `json:"-"`
	NetworkName    string `json:"-"`
	TFVersion      string `json:"tf_version"`
	ConsulURL      string `json:"consul_url"`
	WithConsul     bool   `json:"with_consul"`
	ClientSecret   string `json:"client_secret"`
	TenantID       string `json:"tenant_id"`
	SubscriptionID string `json:"subscription_id"`
}
