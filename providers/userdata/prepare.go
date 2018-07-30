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

package userdata

//go:generate rice embed-go

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/utils"
	rice "github.com/GeertJohan/go.rice"
)

// userData is the structure to apply to userdata.sh template
type userData struct {
	// User is the name of the default user (api.DefaultUser)
	User string
	// Key is the private key used to create the Host
	Key string
	// ConfIF, if set to true, configure all interfaces to DHCP
	ConfIF bool
	// IsGateway, if set to true, activate IP frowarding
	IsGateway bool
	// AddGateway, if set to true, configure default gateway
	AddGateway bool
	// DNSServers contains the list of DNS servers to use
	// Used only if IsGateway is true
	DNSServers []string
	// GatewayIP is the IP of the gateway
	GatewayIP string
	// Password for the user gpac (for troubleshoot use, useable only in console)
	Password string
}

var userdataTemplate *template.Template

// Prepare prepares the initial configuration script executed by cloud compute resource
func Prepare(client api.ClientAPI, request api.VMRequest, isGateway bool, kp *api.KeyPair, gw *api.VM) ([]byte, error) {
	// Generate password for user gpac
	gpacPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password: %s", err.Error())
	}

	// Determine Gateway IP
	ip := ""
	if gw != nil {
		if len(gw.PrivateIPsV4) > 0 {
			ip = gw.PrivateIPsV4[0]
		} else if len(gw.PrivateIPsV6) > 0 {
			ip = gw.PrivateIPsV6[0]
		}
	}

	var (
		anon                      interface{}
		ok                        bool
		autoHostNetworkInterfaces bool
		useLayer3Networking       = true
		dnsList                   []string
	)
	config, err := client.GetCfgOpts()
	if err != nil {
		return nil, nil
	}
	anon, ok = config.Get("AutoHostNetworkInterfaces")
	if ok {
		autoHostNetworkInterfaces = anon.(bool)
	}
	anon, ok = config.Get("UseLayer3Networking")
	if ok {
		useLayer3Networking = anon.(bool)
	}
	anon, ok = config.Get("DNSList")
	if ok {
		dnsList = anon.([]string)
	} else {
		dnsList = []string{"1.1.1.1"}
	}

	data := userData{
		User:       api.DefaultUser,
		Key:        strings.Trim(kp.PublicKey, "\n"),
		ConfIF:     !autoHostNetworkInterfaces,
		IsGateway:  isGateway && !useLayer3Networking,
		AddGateway: !request.PublicIP && !useLayer3Networking,
		DNSServers: dnsList,
		GatewayIP:  ip,
		Password:   gpacPassword,
	}

	dataBuffer := bytes.NewBufferString("")
	err = userdataTemplate.Execute(dataBuffer, data)
	if err != nil {
		return nil, err
	}
	return dataBuffer.Bytes(), nil
}

func initUserdataTemplate() error {
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

func init() {
	err := initUserdataTemplate()
	if err != nil {
		panic(fmt.Sprintf("providers.userdata.init(): %v", err))
	}
}
