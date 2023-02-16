//go:build debug
// +build debug

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

package userdata

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	txttmpl "text/template"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
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
	SSHPort                     string                        // Define Gateway SSHport
	PublicIP                    string                        // contains a public IP bound to the host
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
	Debug                       bool
	WithoutFirewall             bool
	DefaultFirewall             bool
	// Dashboard bool // Add kubernetes dashboard
}

var (
	userdataScriptTemplates = map[Phase]*atomic.Value{
		PHASE1_INIT:                      nil,
		PHASE2_NETWORK_AND_SECURITY:      nil,
		PHASE3_GATEWAY_HIGH_AVAILABILITY: nil,
		PHASE4_SYSTEM_FIXES:              nil,
		PHASE5_FINAL:                     nil,
	}
	userdataScriptTemplatesLock sync.RWMutex
	userdataScriptProvider      string
	userdataScripts             = map[Phase]string{
		PHASE1_INIT:                      "newscripts/userdata%s.init.sh",
		PHASE2_NETWORK_AND_SECURITY:      "newscripts/userdata%s.netsec.sh",
		PHASE3_GATEWAY_HIGH_AVAILABILITY: "newscripts/userdata%s.gwha.sh",
		PHASE4_SYSTEM_FIXES:              "newscripts/userdata%s.sysfix.sh",
		PHASE5_FINAL:                     "newscripts/userdata%s.final.sh",
	}
)

// NewContent ...
func NewContent() *Content {
	return &Content{
		Tags: map[Phase]map[string][]string{},
	}
}

// OK ...
func (ud Content) OK() bool {
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

	if debugFlag := os.Getenv("SAFESCALE_DEBUG"); debugFlag != "" {
		ud.Debug = true
	}

	if debugFlag := os.Getenv("SAFESCALE_DEBUG"); debugFlag == "NoFirewall" {
		ud.WithoutFirewall = true
	}

	if debugFlag := os.Getenv("SAFESCALE_DEBUG"); debugFlag == "DefaultFirewall" {
		ud.DefaultFirewall = true
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
	ud.SSHPort = strconv.Itoa(int(request.SSHPort))
	if request.SSHPort <= 0 {
		ud.SSHPort = "22"
	}
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

	// Generate a keypair for first SSH connection, that will then be replaced by FinalPxxxKey during phase2
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

//go:embed newscripts/*
var scripts embed.FS

// Generate generates the script file corresponding to the phase
func (ud *Content) Generate(phase Phase) ([]byte, fail.Error) {
	var (
		result []byte
		err    error
	)

	userdataScriptTemplatesLock.Lock()
	defer userdataScriptTemplatesLock.Unlock()

	anon, ok := userdataScriptTemplates[phase]
	if !ok {
		return nil, fail.InvalidParameterError("phase '%s' not managed", phase)
	}

	var tmpl *txttmpl.Template
	if anon != nil {
		tmpl, ok = anon.Load().(*txttmpl.Template)
		if !ok {
			return nil, fail.NewError("error loading template for phase '%s'", phase)
		}
	} else {
		// FIXME: OPP If /tmp/+ userdataScripts[phase] exists, use the local file
		var tmplString []byte
		tmplString, err = scripts.ReadFile(fmt.Sprintf(userdataScripts[phase], userdataScriptProvider))
		if err != nil {
			return nil, fail.Wrap(err, "error loading script template for phase 'init'")
		}

		tmpl, err = template.Parse("userdata."+string(phase), string(tmplString))
		if err != nil {
			return nil, fail.Wrap(err, "error parsing script template for phase 'init'")
		}

		userdataScriptTemplates[phase] = new(atomic.Value)
		userdataScriptTemplates[phase].Store(tmpl)
	}

	if tmpl == nil {
		return nil, fail.InconsistentError("failed to recover userdata script for phase '%s'", phase)
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
		err = os.WriteFile(dumpName, result, 0644)
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

// checkScriptFilePresents ...
// returns:
//   - nil: files found
//   - *fail.ErrNotFound: at least one file with suffix != "" is not found
//   - *fail.ErrInconsistent: at least one mandatory file is missing
func checkScriptFilePresents(suffix string) fail.Error {
	var (
		missing Phase
		problem bool
	)
	for k, v := range userdataScripts {
		_, err := scripts.ReadFile(fmt.Sprintf(v, suffix))
		problem = problem || (err != nil)
		if problem {
			missing = k
			break
		}
	}
	if problem {
		if suffix != "" {
			return fail.Wrap(fail.NotFoundError("missing userdata script 'userdata.%s.%s.sh' in binary", suffix, missing), "ignoring script flavor '%s'", suffix)
		}
		return fail.InconsistentError("missing mandatory userdata script 'userdata.%s.sh' in binary", missing)
	}

	return nil
}

// init checks at start if all needed userdata scripts are present in binary
func init() {
	suffixCandidate := os.Getenv("SAFESCALE_SCRIPT_FLAVOR")
	xerr := checkScriptFilePresents(suffixCandidate)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// ignore suffixCandidate but still check "traditional" mandatory files are present
			if suffixCandidate != "" {
				xerr = checkScriptFilePresents("")
				if xerr != nil {
					panic(xerr.Error())
				}
			}
		default:
			panic(xerr.Error())
		}
	}

	if suffixCandidate != "" {
		userdataScriptProvider = suffixCandidate
	}
}
