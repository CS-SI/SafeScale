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

package openstack

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ParseBadRequest parses BadRequest JSON error and returns fields
func ParseBadRequest(badRequestError string) map[string]string {
	startIdx := strings.Index(badRequestError, "{\"badRequest\":")
	jsonError := strings.Trim(badRequestError[startIdx:], " ")
	unjsoned := map[string]map[string]interface{}{}
	err := json.Unmarshal([]byte(jsonError), &unjsoned)
	if err != nil {
		log.Debugf(err.Error())
		return nil
	}
	if content, ok := unjsoned["badRequest"]; ok {
		retval := map[string]string{
			"message": "",
			"type":    "",
			"code":    "",
			"detail":  "",
		}
		if field, ok := content["message"].(string); ok {
			retval["message"] = field
		}
		if field, ok := content["type"].(string); ok {
			retval["type"] = field
		}
		if field, ok := content["code"].(float64); ok {
			retval["code"] = fmt.Sprintf("%d", int(field))
		}
		if field, ok := content["detail"].(string); ok {
			retval["detail"] = field
		}
		return retval
	}
	return nil
}

// ParseNeutronError parses neutron json error and returns fields
func ParseNeutronError(neutronError string) map[string]string {
	startIdx := strings.Index(neutronError, "{\"NeutronError\":")
	jsonError := strings.Trim(neutronError[startIdx:], " ")
	unjsoned := map[string]map[string]interface{}{}
	err := json.Unmarshal([]byte(jsonError), &unjsoned)
	if err != nil {
		log.Debugf(err.Error())
		return nil
	}
	if content, ok := unjsoned["NeutronError"]; ok {
		retval := map[string]string{
			"message": "",
			"type":    "",
			"code":    "",
			"detail":  "",
		}
		if field, ok := content["message"].(string); ok {
			retval["message"] = field
		}
		if field, ok := content["type"].(string); ok {
			retval["type"] = field
		}
		if field, ok := content["code"].(string); ok {
			retval["code"] = field
		}
		if field, ok := content["detail"].(string); ok {
			retval["detail"] = field
		}

		return retval
	}
	return nil
}
