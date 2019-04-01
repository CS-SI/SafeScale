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

package userdata

//go:generate rice embed-go

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"text/template"

	rice "github.com/GeertJohan/go.rice"

	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/stacks"
	"github.com/CS-SI/SafeScale/utils"
)

// userData is the structure to apply to userdata.sh template
type userData struct {
	// Header is the bash header for scripts
	BashHeader string
	// User is the name of the default user (api.DefaultUser)
	User string
	// PublicKey is the public key used to create the Host
	PublicKey string
	// PrivateKey is the private key used to create the Host
	PrivateKey string
	// ConfIF, if set to true, configure all interfaces to DHCP
	ConfIF bool
	// IsGateway, if set to true, activate IP frowarding
	IsGateway bool
	// AddGateway, if set to true, configure default gateway
	AddGateway bool
	// DNSServers contains the list of DNS servers to use
	// Used only if IsGateway is true
	DNSServers []string
	//CIDR contains the cidr of the network
	CIDR string
	// GatewayIP is the IP of the gateway
	GatewayIP string
	// Password for the user safescale (for troubleshoot use, useable only in console)
	Password string
	// EmulatedPublicNet is a private network which is used to emulate a public one
	EmulatedPublicNet string
	// HostName contains the name wanted as host name (default == name of the Cloud resource)
	HostName string
}

var userdataTemplate *template.Template

// Prepare prepares the initial configuration script executed by cloud compute resource
func Prepare(
	options stacks.ConfigurationOptions, request resources.HostRequest, cidr string, defaultNetworkCIDR string,
) ([]byte, error) {

	// Generate password for user safescale
	var (
		err                       error
		autoHostNetworkInterfaces bool
		useLayer3Networking       = true
		dnsList                   []string
		operatorUsername          string
	)
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, fmt.Errorf("failed to generate password: %s", err.Error())
		}
		request.Password = password
	}

	// Determine Gateway IP
	ip := ""
	if request.DefaultGateway != nil {
		ip = request.DefaultGateway.GetPrivateIP()
	}

	autoHostNetworkInterfaces = options.AutoHostNetworkInterfaces
	useLayer3Networking = options.UseLayer3Networking
	operatorUsername = options.OperatorUsername
	dnsList = options.DNSList
	if len(dnsList) <= 0 {
		dnsList = []string{"1.1.1.1"}
	}

	if userdataTemplate == nil {
		b, err := rice.FindBox("../userdata/scripts")
		if err != nil {
			return nil, err
		}
		tmplString, err := b.String("userdata.sh")
		if err != nil {
			return nil, fmt.Errorf("error loading script template: %s", err.Error())
		}
		userdataTemplate, err = template.New("userdata").Parse(tmplString)
		if err != nil {
			return nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
	}

	scriptHeader := "set -u -o pipefail"
	if suffixCandidate := os.Getenv("SAFESCALE_SCRIPTS_FAIL_FAST"); suffixCandidate != "" {
		if strings.EqualFold("True", strings.TrimSpace(suffixCandidate)) {
			scriptHeader = "set -Eeuxo pipefail"
		}

		if strings.EqualFold("1", strings.TrimSpace(suffixCandidate)) {
			scriptHeader = "set -Eeuxo pipefail"
		}
	}

	data := userData{
		BashHeader:        scriptHeader,
		User:              operatorUsername,
		PublicKey:         strings.Trim(request.KeyPair.PublicKey, "\n"),
		PrivateKey:        strings.Trim(request.KeyPair.PrivateKey, "\n"),
		ConfIF:            !autoHostNetworkInterfaces,
		IsGateway:         request.DefaultGateway == nil && request.Networks[0].Name != resources.SingleHostNetworkName && !useLayer3Networking,
		AddGateway:        !request.PublicIP && !useLayer3Networking,
		DNSServers:        dnsList,
		CIDR:              cidr,
		GatewayIP:         ip,
		Password:          request.Password,
		EmulatedPublicNet: defaultNetworkCIDR,
		//HostName:   request.Name,
	}

	dataBuffer := bytes.NewBufferString("")
	err = userdataTemplate.Execute(dataBuffer, data)
	if err != nil {
		return nil, err
	}
	return dataBuffer.Bytes(), nil
}

//Append add some usefull code on the end of userdata.sh just before the reboot (on the label #insert_tag)
func Append(userdata []byte, addedPart string) []byte {
	return bytes.Replace(userdata, []byte("#insert_tag"), []byte(addedPart+"\n\n#insert_tag"), 1)
}

func initUserdataTemplate() error {
	if userdataTemplate != nil {
		// Already loaded
		return nil
	}

	var (
		err         error
		box         *rice.Box
		userdataStr string
	)

	box, err = rice.FindBox("../userdata/scripts")
	if err == nil {
		userdataStr, err = box.String("userdata.sh")
		if err == nil {
			userdataTemplate, err = template.New("user_data").Parse(userdataStr)
			if err == nil {
				return nil
			}
		}
	}
	return err
}
