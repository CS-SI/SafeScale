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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package securityflavor

//go:generate stringer -type=Enum

//Enum represents the state of a node
type Enum int

const (
	//Sys indicates the default no-cryptographic security
	Sys Enum = iota
	//Krb5 indicates Kerberos5 authentication only
	Krb5
	//Krb5i indicates Kerberos5 with integrity protection
	Krb5i
	//Krb5p indicates Kerberos5 with privacy protection
	Krb5p
)
