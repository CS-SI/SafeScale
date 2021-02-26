/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package operations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/template"
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
	subnet resources.Subnet
	// host      *pb.IPAddress
	// safescale safescale.Client

	gateway          resources.Host
	gatewayPrivateIP string
	gatewayPublicIP  string
}

// NewKongController ...
func NewKongController(svc iaas.Service, subnet resources.Subnet, addressPrimaryGateway bool) (*KongController, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if subnet == nil {
		return nil, fail.InvalidParameterCannotBeNilError("subnet")
	}

	// Check if 'edgeproxy4subnet' feature is installed on host
	voidtask, xerr := concurrency.NewTask()
	if xerr != nil {
		return nil, xerr
	}

	rp, xerr := NewFeature(voidtask, svc, "edgeproxy4subnet")
	if xerr != nil {
		return nil, xerr
	}

	addressedGateway, xerr := subnet.InspectGateway(voidtask, addressPrimaryGateway)
	if xerr != nil {
		return nil, xerr
	}

	present := false
	if anon, ok := kongProxyCheckedCache.Get(subnet.GetName()); ok {
		present = anon.(bool)
	} else {
		setErr := kongProxyCheckedCache.SetBy(subnet.GetName(), func() (interface{}, fail.Error) {
			results, xerr := rp.Check(addressedGateway, data.Map{}, resources.FeatureSettings{})
			if xerr != nil {
				return false, fail.Wrap(xerr, "failed to check if feature 'edgeproxy4subnet' is installed on gateway '%s'", addressedGateway.GetName())
			}
			if !results.Successful() {
				return false, fail.NotFoundError("feature 'edgeproxy4subnet' is not installed on gateway '%s'", addressedGateway.GetName())
			}

			return true, nil
		})
		if setErr != nil {
			return nil, setErr
		}
		present = true
	}
	if !present {
		return nil, fail.NotFoundError("'edgeproxy4subnet' feature is not installed on gateway '%s'", addressedGateway.GetName())
	}

	ctrl := &KongController{
		subnet:  subnet,
		gateway: addressedGateway,
	}
	if ctrl.gatewayPrivateIP, xerr = addressedGateway.GetPrivateIP(voidtask); xerr != nil {
		return nil, xerr
	}
	if ctrl.gatewayPublicIP, xerr = addressedGateway.GetPublicIP(voidtask); xerr != nil {
		return nil, xerr
	}

	return ctrl, nil
}

// Apply applies the rule to Kong proxy
// Currently, support rule types service, route and upstream
// Returns rule name and error
func (k *KongController) Apply(rule map[interface{}]interface{}, values *data.Map) (string, fail.Error) {
	ruleType, ok := rule["type"].(string)
	if !ok {
		return "", fail.InvalidParameterError("rule['type']", "is not a string")
	}

	ruleName, xerr := k.realizeRuleData(strings.Trim(rule["name"].(string), "\n"), *values)
	if xerr != nil {
		return rule["name"].(string), xerr
	}

	content, xerr := k.realizeRuleData(strings.Trim(rule["content"].(string), "\n"), *values)
	if xerr != nil {
		return ruleName, xerr
	}

	var sourceControl map[string]interface{}

	// Sets the values usable in all cases
	voidtask, xerr := concurrency.NewTask()
	if xerr != nil {
		return "", xerr
	}
	xerr = k.subnet.Inspect(voidtask, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		if as.VIP != nil {
			// VPL: for now, no public IP on VIP, so uses the IP of the first getGateway
			// (*values)["EndpointIP"] = as.VIP.getPublicIP
			(*values)["EndpointIP"] = k.gatewayPublicIP
			(*values)["DefaultRouteIP"] = as.VIP.PrivateIP
		} else {
			(*values)["EndpointIP"] = k.gatewayPublicIP
			(*values)["DefaultRouteIP"] = k.gatewayPrivateIP
		}
		return nil
	})
	if xerr != nil {
		return "", xerr
	}

	// Legacy...
	(*values)["PublicIP"] = (*values)["EndpointIP"]
	(*values)["GatewayIP"] = (*values)["DefaultRouteIP"]

	// Analyze the rule...
	switch ruleType {
	case "service":
		unjsoned := map[string]interface{}{}
		err := json.Unmarshal([]byte(content), &unjsoned)
		if err != nil {
			return ruleName, fail.SyntaxError("syntax error in rule '%s': %s", ruleName, err.Error())
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
		response, _, xerr := k.put(ruleName, url, content, values, true)
		if xerr != nil {
			return ruleName, fail.Wrap(xerr, "failed to apply proxy rule '%s'", ruleName)
		}
		logrus.Debugf("successfully applied proxy rule '%s': %v", ruleName, content)
		return ruleName, k.addSourceControl(ruleName, url, ruleType, response["id"].(string), sourceControl, values)

	case "route":
		unjsoned := map[string]interface{}{}
		err := json.Unmarshal([]byte(content), &unjsoned)
		if err != nil {
			return ruleName, fail.SyntaxError("syntax error in rule '%s': %s", ruleName, err.Error())
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
		response, _, xerr := k.put(ruleName, url, content, values, true)
		if xerr != nil {
			return ruleName, fail.Wrap(xerr, "failed to apply proxy rule '%s'", ruleName)
		}
		logrus.Debugf("successfully applied proxy rule '%s': %v", ruleName, content)
		return ruleName, k.addSourceControl(ruleName, url, ruleType, response["id"].(string), sourceControl, values)

	case "upstream":
		// Separate upstream options from target settings
		unjsoned := data.Map{}
		err := json.Unmarshal([]byte(content), &unjsoned)
		if err != nil {
			return ruleName, fail.SyntaxError("syntax error in rule '%s': %s", ruleName, err.Error())
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
		if xerr = k.createUpstream(ruleName, options, values); xerr != nil {
			return ruleName, xerr
		}
		// }

		// Now ready to add target to upstream
		jsoned, _ := json.Marshal(&target)
		content = string(jsoned)
		url := "upstreams/" + ruleName + "/targets"
		_, _, xerr = k.post(ruleName, url, content, values, false)
		if xerr != nil {
			return ruleName, fail.Wrap(xerr, "failed to apply proxy rule '%s'", ruleName)
		}
		logrus.Debugf("successfully applied proxy rule '%s': %v", ruleName, content)
		return ruleName, nil

	default:
		return ruleName, fail.SyntaxError("syntax error in rule '%s': '%s' isn't a valid type", ruleName, ruleType)
	}
}

func (k *KongController) realizeRuleData(content string, v data.Map) (string, fail.Error) {
	contentTmpl, xerr := template.Parse("proxy_content", content)
	if xerr != nil {
		return "", fail.Wrap(xerr, "error preparing rule")
	}
	dataBuffer := bytes.NewBufferString("")
	err := contentTmpl.Execute(dataBuffer, v)
	if err != nil {
		return "", fail.ConvertError(err)
	}
	return dataBuffer.String(), nil
}

func (k *KongController) createUpstream(name string, options data.Map, v *data.Map) fail.Error {
	jsoned, _ := json.Marshal(&options)
	response, _, xerr := k.put(name, "upstreams/"+name, string(jsoned), v, true)
	if xerr != nil {
		return xerr
	}
	if msg, ok := response["message"]; ok {
		return fail.NewError("failed to create upstream: %s", msg)
	}
	return nil
}

func (k *KongController) addSourceControl(
	ruleName, url, resourceType, resourceID string,
	sourceControl map[string]interface{},
	v *data.Map,
) fail.Error {

	if sourceControl == nil {
		return nil
	}

	// Determine if source-control is already set
	ref := ""
	// url += fmt.Sprintf("%s/plugins", resourceID)
	url += "/plugins"
	result, _, xerr := k.get(ruleName, url)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return xerr
		}
	}

	if kongdata, ok := result["data"].([]interface{}); ok && len(kongdata) > 0 {
		for _, i := range kongdata {
			plugin, ok := i.(map[string]interface{})
			if !ok {
				return fail.InvalidParameterError("result['data']", "is an invalid map[string]")
			}

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
		_, _, xerr = k.post(ruleName, url, string(jsoned), v, false)
	} else {
		_, _, xerr = k.patch(ref, "plugins/", string(jsoned), v, false)
	}
	if xerr != nil {
		xerr = fail.Wrap(xerr, "failed to apply setting 'source-control' of proxy rule '%s'", ruleName)
		logrus.Debugf(strprocess.Capitalize(xerr.Error()))
		return xerr
	}
	return nil
}

func (k *KongController) get(name, url string) (map[string]interface{}, string, fail.Error) {
	cmd := fmt.Sprintf(curlGet, url)
	task, xerr := concurrency.NewTask()
	if xerr != nil {
		return nil, "", xerr
	}

	retcode, stdout, _, xerr := k.gateway.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		return nil, "", xerr
	}

	if retcode != 0 {
		return nil, "", fail.NewError("get '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, xerr := k.parseResult(stdout)
	if xerr != nil {
		return nil, httpcode, xerr
	}

	return response, httpcode, nil
}

// post creates a rule
func (k *KongController) post(name, url, data string, v *data.Map, propagate bool) (map[string]interface{}, string, fail.Error) {
	task, xerr := concurrency.NewTask()
	if xerr != nil {
		return nil, "", xerr
	}

	cmd := fmt.Sprintf(curlPost, url, data)
	retcode, stdout, stderr, xerr := k.gateway.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		return nil, "", xerr
	}
	if retcode != 0 {
		logrus.Debugf("submit of rule '%s' failed on primary gateway: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode, stdout, stderr)
		return nil, "", fail.NewError("submit of rule '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, xerr := k.parseResult(stdout)
	if xerr != nil {
		return nil, httpcode, xerr
	}

	if propagate {
		if id, ok := response["id"]; ok {
			(*v)[name] = id.(string)
		}
	}
	return response, httpcode, nil
}

// put updates or creates a rule
func (k *KongController) put(name, url, data string, v *data.Map, propagate bool) (map[string]interface{}, string, fail.Error) {
	task, xerr := concurrency.NewTask()
	if xerr != nil {
		return nil, "", xerr
	}

	cmd := fmt.Sprintf(curlPut, url, data)
	retcode, stdout, stderr, xerr := k.gateway.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		return nil, "", xerr
	}
	if retcode != 0 {
		logrus.Debugf("submit of rule '%s' failed: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode, stdout, stderr)
		return nil, "", fail.NewError("submit of rule '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, xerr := k.parseResult(stdout)
	if xerr != nil {
		return nil, httpcode, xerr
	}

	if propagate {
		if id, ok := response["id"]; ok {
			(*v)[name] = id.(string)
		}
	}
	return response, httpcode, nil
}

// patch updates an existing rule
func (k *KongController) patch(name, url, data string, v *data.Map, propagate bool) (map[string]interface{}, string, fail.Error) {
	task, xerr := concurrency.NewTask()
	if xerr != nil {
		return nil, "", xerr
	}

	cmd := fmt.Sprintf(curlPatch, url+name, data)
	retcode, stdout, stderr, xerr := k.gateway.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		return nil, "", xerr
	}
	if retcode != 0 {
		logrus.Debugf("update of rule '%s' failed: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode, stdout, stderr)
		return nil, "", fail.NewError("update of rule '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, xerr := k.parseResult(stdout)
	if xerr != nil {
		return nil, httpcode, xerr
	}

	if propagate {
		if id, ok := response["id"]; ok {
			(*v)[name] = id.(string)
		}
	}
	return response, httpcode, nil
}

func (k *KongController) parseResult(result string) (map[string]interface{}, string, fail.Error) {
	output := strings.Split(result, "\n")
	httpcode := output[1]

	var response map[string]interface{}
	err := json.Unmarshal([]byte(output[0]), &response)
	if err != nil {
		return nil, "", fail.ConvertError(err)
	}

	switch httpcode {
	case "200":
		fallthrough
	case "201":
		return response, httpcode, nil
	case "404":
		if msg, ok := response["message"]; ok {
			return nil, httpcode, fail.NotFoundError(msg.(string))
		}
		return nil, output[1], fail.NotFoundError("")
	case "409":
		if msg, ok := response["message"]; ok {
			return nil, httpcode, fail.DuplicateError(msg.(string))
		}
		return nil, httpcode, fail.DuplicateError("")
	default:
		if msg, ok := response["message"]; ok {
			return response, httpcode, fail.NewError("post failed: HTTP error code=%s: %s", httpcode, msg.(string))
		}
		return response, httpcode, fail.NewError("post failed with HTTP error code '%s'", httpcode)
	}
}
