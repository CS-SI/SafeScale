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

package userdata

//go:generate rice embed-go

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	txttmpl "text/template"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/template"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Content is the structure to apply to userdata.sh template
type Content struct {
	// BashLibrary contains the bash library
	system.BashLibraryDefinition

	Header                      string                        // is the bash header for scripts
	Revision                    string                        // is the git revision used to build SafeScale
	Username                    string                        // is the name of the default user (api.DefaultUser)
	ExitOnError                 string                        // helper to quit script on error
	Password                    string                        // for the user safescale (for troubleshoot use, usable only in console)
	FirstPublicKey              string                        // is the public key used for first connection after Host creation
	FirstPrivateKey             string                        // is the private key used for first connection after Host creation
	FinalPublicKey              string                        // is the public key used to connect to Host starting phase3 (disabling FirstPublicKey)
	FinalPrivateKey             string                        // is the private key used to connect tp Host starting phase3 (disabling FirstPrivateKey)
	ConfIF                      bool                          // if set to true, configure all interfaces to DHCP
	IsGateway                   bool                          // if set to true, activate IP forwarding
	PublicIP                    string                        // contains a public IP binded to the host
	AddGateway                  bool                          // if set to true, configure default gateway
	DNSServers                  []string                      // contains the list of DNS servers to use; used only if IsGateway is true
	CIDR                        string                        // contains the cidr of the network
	DefaultRouteIP              string                        // is the IP of the gateway or the VIP if gateway HA is enabled
	EndpointIP                  string                        // is the IP of the gateway or the VIP if gateway HA is enabled
	PrimaryGatewayPrivateIP     string                        // is the private IP of the primary gateway
	PrimaryGatewayPublicIP      string                        // is the public IP of the primary gateway
	SecondaryGatewayPrivateIP   string                        // is the private IP of the secondary gateway
	SecondaryGatewayPublicIP    string                        // is the public IP of the secondary gateway
	EmulatedPublicNet           string                        // is a private network which is used to emulate a public one
	HostName                    string                        // contains the name wanted as host name (default == name of the Cloud resource)
	Tags                        map[Phase]map[string][]string // contains tags and their content(s); a tag is named #<tag> in the template
	IsPrimaryGateway            bool                          // tells if the host is a primary gateway
	GatewayHAKeepalivedPassword string                        // contains the password to use in keepalived configurations
	ProviderName                string
	BuildSubnetworks            bool
	// Dashboard bool // Add kubernetes dashboard
}

var (
	userdataPhaseTemplates = map[Phase]*atomic.Value{
		PHASE1_INIT:                      nil,
		PHASE2_NETWORK_AND_SECURITY:      nil,
		PHASE3_GATEWAY_HIGH_AVAILABILITY: nil,
		PHASE4_SYSTEM_FIXES:              nil,
		PHASE5_FINAL:                     nil,
	}
	userdataPhaseTemplatesLock sync.RWMutex
)

// NewContent ...
func NewContent() *Content {
	return &Content{
		Tags: map[Phase]map[string][]string{},
	}
}

// OK ...
func (ud Content) OK() bool { // FIXME: Complete function, mark struct fields as optional, then validate
	result := true
	result = result && ud.BashLibraryDefinition.Content != ""
	result = result && ud.HostName != ""
	return result
}

// Prepare prepares the initial configuration script executed by cloud compute resource
func (ud *Content) Prepare(
	options stacks.ConfigurationOptions, request abstract.HostRequest, cidr string, defaultNetworkCIDR string,
	timings temporal.Timings,
) fail.Error {
	if ud == nil {
		return fail.InvalidInstanceError()
	}

	// Generate password for user safescale
	var (
		// autoHostNetworkInterfaces bool
		useLayer3Networking bool
		dnsList             []string
		operatorUsername    string
		useNATService       bool
	)
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return fail.Wrap(err, "failed to generate password")
		}
		request.Password = password
	}

	// Determine default route IP
	ip := ""
	if request.DefaultRouteIP != "" {
		ip = request.DefaultRouteIP
	}

	// autoHostNetworkInterfaces = options.AutoHostNetworkInterfaces
	useLayer3Networking = options.UseLayer3Networking
	useNATService = options.UseNATService
	operatorUsername = options.OperatorUsername
	dnsList = options.DNSList
	if len(dnsList) == 0 {
		dnsList = []string{"1.1.1.1"}
	}

	bashLibraryDefinition, xerr := system.BuildBashLibraryDefinition(timings)
	if xerr != nil {
		return xerr
	}

	exitOnErrorHeader := ""
	scriptHeader := "set -u -o pipefail"
	if suffixCandidate := os.Getenv("SAFESCALE_SCRIPTS_FAIL_FAST"); suffixCandidate != "" {
		if strings.EqualFold("True", strings.TrimSpace(suffixCandidate)) ||
			strings.EqualFold("1", strings.TrimSpace(suffixCandidate)) {
			scriptHeader = "set -Eeuxo pipefail"
			exitOnErrorHeader = "echo 'PROVISIONING_ERROR: 222'"
		}
	}

	ud.BashLibraryDefinition = *bashLibraryDefinition
	ud.Header = scriptHeader
	ud.Revision = REV
	ud.Username = operatorUsername
	ud.ExitOnError = exitOnErrorHeader
	ud.FinalPublicKey = strings.Trim(request.KeyPair.PublicKey, "\n")
	ud.FinalPrivateKey = strings.Trim(request.KeyPair.PrivateKey, "\n")
	// ud.ConfIF = !autoHostNetworkInterfaces
	ud.IsGateway = request.IsGateway /*&& request.Subnets[0].Name != abstract.SingleHostNetworkName*/
	ud.AddGateway = !request.IsGateway && !request.PublicIP && !useLayer3Networking && ip != "" && !useNATService
	ud.DNSServers = dnsList
	ud.CIDR = cidr
	ud.DefaultRouteIP = ip
	ud.Password = request.Password
	ud.EmulatedPublicNet = defaultNetworkCIDR
	ud.ProviderName = options.ProviderName
	ud.BuildSubnetworks = options.BuildSubnets

	if request.HostName != "" {
		ud.HostName = request.HostName
	} else {
		ud.HostName = request.ResourceName
	}

	// Generate a keypair for first SSH connection, that will then be replace by FinalPxxxKey during phase2
	kp, xerr := abstract.NewKeyPair("")
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create initial Keypair")
	}

	ud.FirstPrivateKey = kp.PrivateKey
	ud.FirstPublicKey = kp.PublicKey

	return nil
}

func (ud Content) ToMap() (map[string]interface{}, fail.Error) {
	jsoned, err := json.Marshal(ud)
	if err != nil {
		return nil, fail.Wrap(err, "failed to convert struct to json")
	}
	var mapped map[string]interface{}
	err = json.Unmarshal(jsoned, &mapped)
	if err != nil {
		return nil, fail.Wrap(err, "failed to convert json string to map")
	}

	return mapped, nil
}

// Generate generates the script file corresponding to the phase
func (ud *Content) Generate(phase Phase) ([]byte, fail.Error) {
	var (
		box    *rice.Box
		result []byte
		err    error
	)

	// DEV VAR
	provider := ""
	if suffixCandidate := os.Getenv("SAFESCALE_SCRIPT_FLAVOR"); suffixCandidate != "" {
		if suffixCandidate != "" {
			problems := false

			box, err = rice.FindBox("../userdata/scripts")
			if err != nil || box == nil {
				problems = true
			}

			if !problems && box != nil {
				_, err = box.String(fmt.Sprintf("userdata%s.init.sh", suffixCandidate))
				problems = err != nil
				_, err = box.String(fmt.Sprintf("userdata%s.netsec.sh", suffixCandidate))
				problems = problems || (err != nil)
				_, err = box.String(fmt.Sprintf("userdata%s.gwha.sh", suffixCandidate))
				problems = problems || (err != nil)
				_, err = box.String(fmt.Sprintf("userdata%s.sysfix.sh", suffixCandidate))
				problems = problems || (err != nil)
				_, err = box.String(fmt.Sprintf("userdata%s.final.sh", suffixCandidate))
				problems = problems || (err != nil)
				if !problems {
					provider = fmt.Sprintf(".%s", suffixCandidate)
				}
			}

			if problems {
				logrus.Warnf("Ignoring script flavor [%s]", suffixCandidate)
			}
		}
	}

	userdataPhaseTemplatesLock.Lock()
	defer userdataPhaseTemplatesLock.Unlock()

	anon, ok := userdataPhaseTemplates[phase]
	if !ok {
		return nil, fail.NotImplementedError("phase '%s' not managed", phase)
	}

	var tmpl *txttmpl.Template
	if anon != nil {
		tmpl, ok = anon.Load().(*txttmpl.Template)
		if !ok {
			return nil, fail.NewError("error loading template for phase %s", phase)
		}
	} else {

		box, err = rice.FindBox("../userdata/scripts")
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		tmplString, err := box.String(fmt.Sprintf("userdata%s.%s.sh", provider, string(phase)))
		if err != nil {
			return nil, fail.Wrap(err, "error loading script template for phase 'init'")
		}

		tmpl, err = template.Parse("userdata."+string(phase), tmplString)
		if err != nil {
			return nil, fail.Wrap(err, "error parsing script template for phase 'init'")
		}

		userdataPhaseTemplates[phase] = new(atomic.Value)
		userdataPhaseTemplates[phase].Store(tmpl)
	}

	if tmpl == nil {
		return nil, fail.NewError("Nil is not a valid template for phase %s", phase)
	}

	// Transforms struct content to map using json
	mapped, xerr := ud.ToMap()
	if xerr != nil {
		return nil, xerr
	}

	buf := bytes.NewBufferString("")
	err = tmpl.Option("missingkey=error").Execute(buf, mapped)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	result = buf.Bytes()
	for tagname, tagcontent := range ud.Tags[phase] {
		for _, str := range tagcontent {
			bytes.Replace(result, []byte("#"+tagname), []byte(str+"\n\n#"+tagname), 1)
		}
	}

	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		_ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", ud.HostName)), 0777)
		dumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata.%s.sh", ud.HostName, phase))
		err = ioutil.WriteFile(dumpName, result, 0644)
		if err != nil { // No need to act on err
			logrus.Warnf("[TRACE] Failure writing step info into %s", dumpName)
		}
	}

	return result, nil
}

// AddInTag adds some useful code on the end of userdata.netsec.sh just before the end (on the label #insert_tag)
func (ud Content) AddInTag(phase Phase, tagname string, content string) {
	if _, ok := ud.Tags[phase]; !ok {
		ud.Tags[phase] = map[string][]string{}
	}
	ud.Tags[phase][tagname] = append(ud.Tags[phase][tagname], content)
}
