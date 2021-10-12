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
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
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

var kongProxyCheckedCache cache.Cache

// KongController allows to control Kong, installed on a host
type KongController struct {
	subnet resources.Subnet
	// host      *pb.IPAddress
	// safescale safescale.Client

	gateway          resources.Host
	gatewayPrivateIP string
	gatewayPublicIP  string
}

// NewKongController creates a controller for Kong
func NewKongController(ctx context.Context, svc iaas.Service, subnet resources.Subnet, addressPrimaryGateway bool) (*KongController, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if subnet == nil {
		return nil, fail.InvalidParameterCannotBeNilError("subnet")
	}

	addressedGateway, xerr := subnet.InspectGateway(addressPrimaryGateway)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	var present bool
	installedFeatures := addressedGateway.InstalledFeatures()
	for _, v := range installedFeatures {
		if v == "edgeproxy4subnet" || v == "reverseproxy" {
			present = true
			break
		}
	}
	if !present {
		// try an active check and update InstalledFeatures if found
		// Check if 'edgeproxy4subnet' feature is installed on host
		featureInstance, xerr := NewFeature(svc, "edgeproxy4subnet")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		results, xerr := featureInstance.Check(ctx, addressedGateway, data.Map{}, resources.FeatureSettings{})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to check if feature 'edgeproxy4subnet' is installed on gateway '%s'", addressedGateway.GetName())
		}

		if results.Successful() {
			xerr = addressedGateway.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(hostproperty.FeaturesV1, func(clonable data.Clonable) (innerXErr fail.Error) {
					featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					item := propertiesv1.NewHostInstalledFeature()
					item.HostContext = true
					item.Requires, innerXErr = featureInstance.GetRequirements()
					if innerXErr != nil {
						return innerXErr
					}
					featuresV1.Installed[featureInstance.GetName()] = item
					return nil
				})
			})
			if xerr != nil {
				return nil, xerr
			}

			present = true
		}

		if !present {
			return nil, fail.NotFoundError("'edgeproxy4subnet' feature is not installed on gateway '%s'", addressedGateway.GetName())
		}
	}

	ctrl := &KongController{
		subnet:  subnet,
		gateway: addressedGateway,
	}
	ctrl.gatewayPrivateIP, xerr = addressedGateway.GetPrivateIP()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	ctrl.gatewayPublicIP, xerr = addressedGateway.GetPublicIP()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return ctrl, nil
}

// GetHostname returns the name of the Host that corresponds to this instance
func (k *KongController) GetHostname() string {
	if k == nil {
		return ""
	}
	return k.gateway.GetName()
}

// Apply applies the rule to Kong proxy
// Currently, support rule types 'service', 'route' and 'upstream'
// Returns rule name and error
func (k *KongController) Apply(rule map[interface{}]interface{}, values *data.Map) (string, fail.Error) {
	ruleType, ok := rule["type"].(string)
	if !ok {
		return "", fail.InvalidParameterError("rule['type']", "is not a string")
	}

	ruleName, xerr := k.realizeRuleData(strings.Trim(rule["name"].(string), "\n"), *values)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return rule["name"].(string), xerr
	}

	content, xerr := k.realizeRuleData(strings.Trim(rule["content"].(string), "\n"), *values)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return ruleName, xerr
	}

	var sourceControl map[string]interface{}

	// Sets the values usable in all cases
	xerr = k.subnet.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if as.VIP != nil {
			// VPL: for now, no public IP on VIP, so uses the IP of the first getGateway
			// (*values)["EndpointIP"] = as.VIP.unsafeGetPublicIP
			(*values)["EndpointIP"] = k.gatewayPublicIP
			(*values)["DefaultRouteIP"] = as.VIP.PrivateIP
		} else {
			(*values)["EndpointIP"] = k.gatewayPublicIP
			(*values)["DefaultRouteIP"] = k.gatewayPrivateIP
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
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
		err = debug.InjectPlannedError(err)
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
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return ruleName, fail.Wrap(xerr, "failed to apply proxy rule '%s'", ruleName)
		}
		logrus.Debugf("successfully applied proxy rule '%s': %v", ruleName, content)
		return ruleName, k.addSourceControl(ruleName, url, ruleType, response["id"].(string), sourceControl, values)

	case "route":
		unjsoned := map[string]interface{}{}
		err := json.Unmarshal([]byte(content), &unjsoned)
		err = debug.InjectPlannedError(err)
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
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return ruleName, fail.Wrap(xerr, "failed to apply proxy rule '%s'", ruleName)
		}
		logrus.Debugf("successfully applied proxy rule '%s': %v", ruleName, content)
		return ruleName, k.addSourceControl(ruleName, url, ruleType, response["id"].(string), sourceControl, values)

	case "upstream":
		// Separate upstream options from target settings
		unjsoned := data.Map{}
		err := json.Unmarshal([]byte(content), &unjsoned)
		err = debug.InjectPlannedError(err)
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

		xerr = k.createUpstream(ruleName, options, values)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return ruleName, xerr
		}

		// Now ready to add target to upstream
		jsoned, _ := json.Marshal(&target)
		content = string(jsoned)
		url := "upstreams/" + ruleName + "/targets"
		_, _, xerr = k.post(ruleName, url, content, values, false)
		xerr = debug.InjectPlannedFail(xerr)
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", fail.Wrap(xerr, "error preparing rule")
	}
	dataBuffer := bytes.NewBufferString("")
	err := contentTmpl.Option("missingkey=error").Execute(dataBuffer, v)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.ConvertError(err)
	}
	return dataBuffer.String(), nil
}

func (k *KongController) createUpstream(name string, options data.Map, v *data.Map) fail.Error {
	jsoned, _ := json.Marshal(&options)
	response, _, xerr := k.put(name, "upstreams/"+name, string(jsoned), v, true)
	xerr = debug.InjectPlannedFail(xerr)
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, "failed to apply setting 'source-control' of proxy rule '%s'", ruleName)
		logrus.Debugf(strprocess.Capitalize(xerr.Error()))
		return xerr
	}
	return nil
}

func (k *KongController) get(name, url string) (map[string]interface{}, string, fail.Error) {
	cmd := fmt.Sprintf(curlGet, url)
	retcode, stdout, _, xerr := k.gateway.Run(context.TODO(), cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, "", xerr
	}

	if retcode != 0 {
		return nil, "", fail.NewError("get '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, xerr := k.parseResult(stdout)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, httpcode, xerr
	}

	return response, httpcode, nil
}

// post creates a rule
func (k *KongController) post(name, url, data string, v *data.Map, propagate bool) (map[string]interface{}, string, fail.Error) {
	cmd := fmt.Sprintf(curlPost, url, data)
	retcode, stdout, stderr, xerr := k.gateway.Run(context.TODO(), cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, "", xerr
	}
	if retcode != 0 {
		logrus.Debugf("submit of rule '%s' failed on primary gateway: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode, stdout, stderr)
		return nil, "", fail.NewError("submit of rule '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, xerr := k.parseResult(stdout)
	xerr = debug.InjectPlannedFail(xerr)
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
	cmd := fmt.Sprintf(curlPut, url, data)
	retcode, stdout, stderr, xerr := k.gateway.Run(context.TODO(), cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, "", xerr
	}
	if retcode != 0 {
		logrus.Debugf("submit of rule '%s' failed: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode, stdout, stderr)
		return nil, "", fail.NewError("submit of rule '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, xerr := k.parseResult(stdout)
	xerr = debug.InjectPlannedFail(xerr)
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
	cmd := fmt.Sprintf(curlPatch, url+name, data)
	retcode, stdout, stderr, xerr := k.gateway.Run(context.TODO(), cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, "", xerr
	}
	if retcode != 0 {
		logrus.Debugf("update of rule '%s' failed: retcode=%d, stdout=>>%s<<, stderr=>>%s<<", name, retcode, stdout, stderr)
		return nil, "", fail.NewError("update of rule '%s' failed: retcode=%d", name, retcode)
	}

	response, httpcode, xerr := k.parseResult(stdout)
	xerr = debug.InjectPlannedFail(xerr)
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
	err = debug.InjectPlannedError(err)
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

func init() {
	var xerr fail.Error
	kongProxyCheckedCache, xerr = cache.NewCache("proxychecks")
	if xerr != nil {
		panic(xerr)
	}
}
