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
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils"
)

// userData is the structure to apply to userdata.sh template
type userData struct {
	// BashLibrary contains the basj library
	BashLibrary string
	// Header is the bash header for scripts
	Header string
	// User is the name of the default user (api.DefaultUser)
	User string
	// PublicKey is the public key used to create the Host
	PublicKey string
	// PrivateKey is the private key used to create the Host
	PrivateKey string
	// ConfIF, if set to true, configure all interfaces to DHCP
	ConfIF bool
	// IsGateway, if set to true, activate IP forwarding
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

var (
	userdataPhase1Template *template.Template
	userdataPhase2Template *template.Template
)

// Prepare prepares the initial configuration script executed by cloud compute resource
func Prepare(
	options stacks.ConfigurationOptions, request resources.HostRequest, cidr string, defaultNetworkCIDR string,
) ([]byte, []byte, error) {

	// Generate password for user safescale
	var (
		err                       error
		autoHostNetworkInterfaces bool
		useLayer3Networking       = true
		dnsList                   []string
		operatorUsername          string
		box                       *rice.Box
	)
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate password: %s", err.Error())
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

	if userdataPhase1Template == nil || userdataPhase2Template == nil {
		box, err = rice.FindBox("../userdata/scripts")
		if err != nil {
			return nil, nil, err
		}
	}
	if userdataPhase1Template == nil {
		tmplString, err := box.String("userdata.phase1.sh")
		if err != nil {
			return nil, nil, fmt.Errorf("error loading script template: %s", err.Error())
		}
		userdataPhase1Template, err = template.New("userdata.phase1").Parse(tmplString)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
	}
	if userdataPhase2Template == nil {
		tmplString, err := box.String("userdata.phase2.sh")
		if err != nil {
			return nil, nil, fmt.Errorf("error loading script template: %s", err.Error())
		}
		userdataPhase2Template, err = template.New("userdata.phase2").Parse(tmplString)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
	}

	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return nil, nil, err
	}

	scriptHeader := "set -u -o pipefail"
	if suffixCandidate := os.Getenv("SAFESCALE_SCRIPTS_FAIL_FAST"); suffixCandidate != "" {
		if strings.EqualFold("True", strings.TrimSpace(suffixCandidate)) ||
			strings.EqualFold("1", strings.TrimSpace(suffixCandidate)) {
			scriptHeader = "set -Eeuxo pipefail"
		}
	}

	data := userData{
		BashLibrary:       bashLibrary,
		Header:            scriptHeader,
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

	bufPhase1 := bytes.NewBufferString("")
	err = userdataPhase1Template.Execute(bufPhase1, data)
	if err != nil {
		return nil, nil, err
	}
	bufPhase2 := bytes.NewBufferString("")
	err = userdataPhase2Template.Execute(bufPhase2, data)
	if err != nil {
		return nil, nil, err
	}
	return bufPhase1.Bytes(), bufPhase2.Bytes(), nil
}

// Append add some useful code on the end of userdata.sh just before the reboot (on the label #insert_tag)
func Append(userdata []byte, addedPart string) []byte {
	return bytes.Replace(userdata, []byte("#insert_tag"), []byte(addedPart+"\n\n#insert_tag"), 1)
}
