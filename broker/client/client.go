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

package client

// Client units the different resources proposed by brokerd as broker client
type Client struct {
	Container container
	Host      host
	Nas       nas
	Network   network
	Ssh       ssh
	Tenant    tenant
	Volume    volume
}

var client = Client{}

const DefaultTimeout = 0

// New returns an instance of broker Client
func New() *Client {
	return &client
}
