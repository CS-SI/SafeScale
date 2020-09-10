/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	"github.com/sirupsen/logrus"

	safescale "github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	curlGet   = "curl -kSsl -X GET --url https://localhost:8444/%s -H \"Content-Type:application/json\" -w \"\\n%%{http_code}\""
	curlPost  = "curl -kSsl -X POST --url https://localhost:8444/%s -H \"Content-Type:application/json\" -w \"\\n%%{http_code}\" -d @- <<'EOF'\n%s\nEOF\n"
	curlPut   = "curl -kSsl -X PUT --url https://localhost:8444/%s -H \"Content-Type:application/json\" -w \"\\n%%{http_code}\" -d @- <<'EOF'\n%s\nEOF\n"
	curlPatch = "curl -kSsl -X PATCH --url https://localhost:8444/%s -H \"Content-Type:application/json\" -w \"\\n%%{http_code}\" -d @- <<'EOF'\n%s\nEOF\n"
)

var kongProxyCheckedCache = utils.NewMapCache()

// KongController allows to control Kong, installed on a host
type KongController struct {
	network *resources.Network
	// host      *pb.Host
	safescale safescale.Client

	gateway          *resources.Host
	gatewayPrivateIP string
	gatewayPublicIP  string
}

// NewKongController ...
// returns:
//    *KongController, nil if successful
//    nil, scerr.ErrNotFound if reverseproxy is not installed
//    nil, scerr.ErrNotAvailable if cannot check if reverseproxy is installed
func NewKongController(svc iaas.Service, network *resources.Network, addressPrimaryGateway bool) (*KongController, error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if network == nil {
		return nil, scerr.InvalidParameterError("network", "cannot be nil")
	}

	// Check if reverseproxy feature is installed on host
	voidtask, err := concurrency.VoidTask()
	if err != nil {
		return nil, err
	}
	rp, err := NewEmbeddedFeature(voidtask, "edgeproxy4network")
	if err != nil {
		return nil, err
	}
	var (
		addressedGateway *resources.Host
	)
	if addressPrimaryGateway {
		mh, err := metadata.LoadHost(svc, network.GatewayID)
		if err != nil {
			return nil, err
		}
		addressedGateway, err = mh.Get()
		if err != nil {
			return nil, err
		}
		if addressedGateway == nil {
			return nil, fmt.Errorf("error getting data of primary gateway")
		}
	} else {
		if network.SecondaryGatewayID == "" {
			return nil, fmt.Errorf("cannot address secondary gateway, doesn't exist")
		}
		mh, err := metadata.LoadHost(svc, network.SecondaryGatewayID)
		if err != nil {
			return nil, err
		}
		addressedGateway, err = mh.Get()
		if err != nil {
			return nil, err
		}

		if addressedGateway == nil {
			return nil, fmt.Errorf("error getting data of secondary gateway")
		}
	}

	present := false
	if anon, ok := kongProxyCheckedCache.Get(network.Name); ok {
		present = anon.(bool)
	} else {
		setErr := kongProxyCheckedCache.SetBy(
			network.Name, func() (interface{}, error) {
				pbHost, err := srvutils.ToPBHost(addressedGateway)
				if err != nil {
					return false, err
				}
				target, err := NewNodeTarget(pbHost)
				if err != nil {
					return false, err
				}
				results, err := rp.Check(target, Variables{}, Settings{})
				if err != nil {
					return false, scerr.NotAvailableError(
						fmt.Sprintf(
							"failed to check if feature 'edgeproxy4network' is installed on gateway '%s': %s",
							err.Error(), addressedGateway.Name,
						),
					)
				}
				if !results.Successful() {
					return false, scerr.NotFoundError(
						fmt.Sprintf(
							"feature 'edgeproxy4network' is not installed on gateway '%s'", addressedGateway.Name,
						),
					)
				}

				return true, nil
			},
		)
		if setErr != nil {
			return nil, setErr
		}
		present = true
	}
	if !present {
		return nil, scerr.NotFoundError(
			fmt.Sprintf(
				"feature 'edgeproxy4network' is not installed on gateway '%s'", addressedGateway.Name,
			),
		)
	}

	ctrl := KongController{
		network: network,
		// host:      host,
		safescale:        safescale.New(),
		gateway:          addressedGateway,
		gatewayPrivateIP: addressedGateway.GetPrivateIP(),
		gatewayPublicIP:  addressedGateway.GetPublicIP(),
	}

	return &ctrl, nil
}

// Apply applies the rule to Kong proxy
// Currently, support rule types service, route and upstream
// Returns rule name and error
func (k *KongController) Apply(rule map[interface{}]interface{}, values *Variables) (string, error) {
	ruleType := rule["type"].(string)

	ruleName, err := k.realizeRuleData(strings.Trim(rule["name"].(string), "\n"), *values)
	if err != nil {
		return rule["name"].(string), err
	}
	content, err := k.realizeRuleData(strings.Trim(rule["content"].(string), "\n"), *values)
	if err != nil {
		return ruleName, err
	}

	var sourceControl map[string]interface{}

	// Sets the values usable in all cases
	if k.network.VIP != nil {
		// VPL: for now, no public IP on VIP, so uses the IP of the first Gateway
		// (*values)["EndpointIP"] = k.network.VIP.PublicIP
		(*values)["EndpointIP"] = k.gatewayPublicIP
		(*values)["DefaultRouteIP"] = k.network.VIP.PrivateIP
	} else {
		(*values)["EndpointIP"] = k.gatewayPublicIP
		(*values)["DefaultRouteIP"] = k.gatewayPrivateIP
	}
	// Legacy...
	(*values)["PublicIP"] = (*values)["EndpointIP"]
	(*values)["GatewayIP"] = (*values)["DefaultRouteIP"]

	// Analyzes the rule...
	switch ruleType {
	case "service":
		unjsoned := map[string]interface{}{}
		err = json.Unmarshal([]byte(content), &unjsoned)
		if err != nil {
			return ruleName, fmt.Errorf("syntax error in rule '%s': %s", ruleName, err.Error())
		}
		if _, ok := unjsoned["source-control"]; ok {
			sourceControl = unjsoned["source-control"].(map[string]interface{})
			delete(unjsoned, "source-control")
		}
		if _, ok := unjsoned["name"]; !ok {
			unjsoned["name"] = ruleName
		}
		jsoned, _ := json.Marshal(&unjsoned)
		content := string(jsoned)

		url := "services/" + ruleName
		response, _, err := k.put(ruleName, url, content, values, true)
		if err != nil {
			return ruleName, fmt.Errorf("failed to apply proxy rule '%s': %s", ruleName, err.Error())
		}
		logrus.Debugf("successfully applied proxy rule '%s': %v", ruleName, content)
		return ruleName, k.addSourceControl(ruleName, url, ruleType, response["id"].(string), sourceControl, values)

	case "route":
		unjsoned := map[string]interface{}{}
		err = json.Unmarshal([]byte(content), &unjsoned)
		if err != nil {
			return ruleName, fmt.Errorf("syntax error in rule '%s': %s", ruleName, err.Error())
		}
		if _, ok := unjsoned["source-control"]; ok {
			sourceControl = unjsoned["source-control"].(map[string]interface{})
			delete(unjsoned, "source-control")
		}
		if _, ok := unjsoned["name"]; !ok {
			unjsoned["name"] = ruleName
		}
		unjsoned["protocols"] = []string{"https"}
		jsoned, _ := json.Marshal(&unjsoned)
		content = string(jsoned)
		url := "routes/" + ruleName
		response, _, err := k.put(ruleName, url, content, values, true)
		if err != nil {
			return ruleName, fmt.Errorf("failed to apply proxy rule '%s': %s", ruleName, err.Error())
		}
		logrus.Debugf("successfully applied proxy rule '%s': %v", ruleName, content)
		return ruleName, k.addSourceControl(ruleName, url, ruleType, response["id"].(string), sourceControl, values)

	case "upstream":
		// Separate upstream options from target settings
		unjsoned := data.Map{}
		err = json.Unmarshal([]byte(content), &unjsoned)
		if err != nil {
			return ruleName, fmt.Errorf("syntax error in rule '%s': %s", ruleName, err.Error())
		}
		options := data.Map{}
		target := data.Map{}
		for k, v := range unjsoned {
			if k == "target" || k == "weight" {
				target[k] = v
				continue
			}
			if k == "tags" {
				target[k] = v
			}
			options[k] = v
		}

		// if create {
		err = k.createUpstream(ruleName, options, values)
		if err != nil {
			return ruleName, err
		}
		// }

		// Now ready to add target to upstream
		jsoned, _ := json.Marshal(&target)
		content = string(jsoned)
		url := "upstreams/" + ruleName + "/targets"
		_, _, err = k.post(ruleName, url, content, values, false)
		if err != nil {
			return ruleName, fmt.Errorf("failed to apply proxy rule '%s': %s", ruleName, err.Error())
		}
		logrus.Debugf("successfully applied proxy rule '%s': %v", ruleName, content)
		return ruleName, nil

	default:
		return ruleName, fmt.Errorf("syntax error in rule '%s': '%s' isn't a valid type", ruleName, ruleType)
	}
}

func (k *KongController) realizeRuleData(content string, v Variables) (string, error) {
	contentTmpl, err := template.New("proxy_content").Parse(content)
	if err != nil {
		return "", fmt.Errorf("error preparing rule: %s", err.Error())
	}
	dataBuffer := bytes.NewBufferString("")
	err = contentTmpl.Execute(dataBuffer, v)
	if err != nil {
		return "", err
	}
	return dataBuffer.String(), nil
}

func (k *KongController) createUpstream(name string, options data.Map, v *Variables) error {
	jsoned, _ := json.Marshal(&options)
	response, _, err := k.put(name, "upstreams/"+name, string(jsoned), v, true)
	if response == nil && err != nil {
		return err
	}
	if msg, ok := response["message"]; ok {
		return fmt.Errorf("failed to create upstream: %s", msg)
	}
	return nil
}

func (k *KongController) addSourceControl(ruleName, url, resourceType, resourceID string, sourceControl map[string]interface{}, v *Variables) error {
	if sourceControl == nil {
		return nil
	}

	// Determine if source-control is already set
	ref := ""
	// url += fmt.Sprintf("%s/plugins", resourceID)
	url += "/plugins"
	result, _, err := k.get(ruleName, url)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return err
		}
	}
	if kongdata, ok := result["data"].([]interface{}); ok && len(kongdata) > 0 {
		for _, i := range kongdata {
			plugin := i.(map[string]interface{})
			if plugin["name"] == "ip-restriction" {
				ref = plugin["id"].(string)
				break
			}
		}
	}

	// Build kongdata to submit to kong
	kongdata := map[string]interface{}{
		"name":       "ip-restriction",
		resourceType: map[string]interface{}{"id": resourceID},
		"config":     sourceControl,
	}
	jsoned, _ := json.Marshal(&kongdata)

	// Create or patch plugin ip-restriction
	if ref == "" {
		_, _, err = k.post(ruleName, url, string(jsoned), v, false)
	} else {
		_, _, err = k.patch(ref, "plugins/", string(jsoned), v, false)
	}
	if err != nil {
		msg := fmt.Sprintf("failed to apply setting 'source-control' of proxy rule '%s': %s", ruleName, err.Error())
		logrus.Debugf(utils.Capitalize(msg))
		return fmt.Errorf(msg)
	}
	return nil
}

func (k *KongController) buildSourceControlContent(rules map[string]interface{}) string {
	kongdata := map[string]interface{}{
		"config": rules,
	}
	kongdata["name"] = "ip-restriction"
	jsoned, _ := json.Marshal(&kongdata)
	return string(jsoned)
}

func (k *KongController) get(name, url string) (map[string]interface{}, string, error) {
	cmd := fmt.Sprintf(curlGet, url)
	retcode, stdout, _, err := safescale.New().SSH.Run(
		k.gateway.Name, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout(),
	)
	if err != nil {
		return nil, "", err
	}
	if retcode != 0 {
		return nil, "", fmt.Errorf("get '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, err := k.parseResult(stdout)
	if err != nil {
		return nil, httpcode, err
	}
	return response, httpcode, nil
}

// post creates a rule
func (k *KongController) post(name, url, data string, v *Variables, propagate bool) (map[string]interface{}, string, error) {
	cmd := fmt.Sprintf(curlPost, url, data)
	retcode, stdout, stderr, err := safescale.New().SSH.Run(
		k.gateway.Name, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout(),
	)
	if err != nil {
		return nil, "", err
	}
	if retcode != 0 {
		logrus.Debugf(
			"submit of rule '%s' failed on primary gateway: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode,
			stdout, stderr,
		)
		return nil, "", fmt.Errorf("submit of rule '%s' failed: retcode=%d", name, retcode)
	}
	response, httpcode, err := k.parseResult(stdout)
	if err != nil {
		return nil, httpcode, err
	}

	if propagate {
		if id, ok := response["id"]; ok {
			(*v)[name] = id.(string)
		}
	}
	return response, httpcode, nil
}

// put updates or creates a rule
func (k *KongController) put(name, url, data string, v *Variables, propagate bool) (map[string]interface{}, string, error) {
	cmd := fmt.Sprintf(curlPut, url, data)
	retcode, stdout, stderr, err := safescale.New().SSH.Run(
		k.gateway.Name, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout(),
	)
	if err != nil {
		return nil, "", err
	}
	if retcode != 0 {
		logrus.Debugf(
			"submit of rule '%s' failed: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode, stdout, stderr,
		)
		return nil, "", fmt.Errorf("submit of rule '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, err := k.parseResult(stdout)
	if err != nil {
		return nil, httpcode, err
	}
	if propagate {
		if id, ok := response["id"]; ok {
			(*v)[name] = id.(string)
		}
	}
	return response, httpcode, nil
}

// patch updates an existing rule
func (k *KongController) patch(name, url, data string, v *Variables, propagate bool) (map[string]interface{}, string, error) {
	cmd := fmt.Sprintf(curlPatch, url+name, data)
	retcode, stdout, stderr, err := safescale.New().SSH.Run(
		k.gateway.Name, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout(),
	)
	if err != nil {
		return nil, "", err
	}
	if retcode != 0 {
		logrus.Debugf(
			"update of rule '%s' failed: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode, stdout, stderr,
		)
		return nil, "", fmt.Errorf("update of rule '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, err := k.parseResult(stdout)
	if err != nil {
		return nil, httpcode, err
	}

	if propagate {
		if id, ok := response["id"]; ok {
			(*v)[name] = id.(string)
		}
	}
	return response, httpcode, nil
}

func (k *KongController) parseResult(result string) (map[string]interface{}, string, error) {
	output := strings.Split(result, "\n")
	httpcode := output[1]

	var response map[string]interface{}
	err := json.Unmarshal([]byte(output[0]), &response)
	if err != nil {
		return nil, "", err
	}

	switch httpcode {
	case "200":
		fallthrough
	case "201":
		return response, httpcode, nil
	case "404":
		if msg, ok := response["message"]; ok {
			return nil, httpcode, scerr.NotFoundError(msg.(string))
		}
		return nil, output[1], scerr.NotFoundError("")
	case "409":
		if msg, ok := response["message"]; ok {
			return nil, httpcode, scerr.DuplicateError(msg.(string))
		}
		return nil, httpcode, scerr.DuplicateError("")
	default:
		if msg, ok := response["message"]; ok {
			return response, httpcode, fmt.Errorf("post failed: HTTP error code=%s: %s", httpcode, msg.(string))
		}
		return response, httpcode, fmt.Errorf("post failed with HTTP error code '%s'", httpcode)
	}
}
