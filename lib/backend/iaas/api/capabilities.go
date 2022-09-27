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

package iaasapi

// Capabilities represents key/value configuration.
type Capabilities struct {
	UseTerraformer          bool // tells if the provider is usiung terraformer or native driver
	PublicVirtualIP         bool // indicates if the Provider has the capability to provide a Virtual IP with public IP address
	PrivateVirtualIP        bool // indicates if the Provider has the capability to provide a Virtual IP with private IP address
	Layer3Networking        bool // indicates if the Provider uses Layer3 networking
	CanDisableSecurityGroup bool // indicates if the Provider supports to disable a Security Group
	// SubnetSecurityGroup bool // indicates if the Provider supports to bind security group to subnet
}
