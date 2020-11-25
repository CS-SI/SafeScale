/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package gcp

import (
	"net/url"
)

// SelfLink ...
type SelfLink = url.URL

// IPInSubnet ...
type IPInSubnet struct {
	Subnet   SelfLink
	Name     string
	ID       string
	IP       string
	PublicIP string
}

func genURL(urlCand string) SelfLink {
	theURL, err := url.Parse(urlCand)
	if err != nil {
		return url.URL{}
	}
	return *theURL
}

// func assertEq(exp, got interface{}) error {
// 	if !reflect.DeepEqual(exp, got) {
// 		return fmt.Errorf("wanted %v; Got %v", exp, got)
// 	}
// 	return nil
// }
