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

package operations

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// FeatureParameter describes a Feature parameter as defined by Feature file content
type FeatureParameter struct {
	name             string // contains the name of the parameter
	description      string // contains the description of the parameter
	defaultValue     string // contains default value of the parameter
	valueControlCode string
	hasDefaultValue  bool // true if the parameter has a default value
	hasValueControl  bool
}

// NewFeatureParameter initiales an new instance of FeatureParameter
func NewFeatureParameter(name, description string, hasDefault bool, defaultValue string, hasValueControl bool, valueControlCode string) (FeatureParameter, fail.Error) {
	if name == "" {
		return FeatureParameter{}, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	out := FeatureParameter{
		name:             name,
		description:      description,
		hasDefaultValue:  hasDefault,
		defaultValue:     defaultValue,
		hasValueControl:  hasValueControl,
		valueControlCode: valueControlCode,
	}
	return out, nil
}

// Name returns the name of the parameter
func (fp FeatureParameter) Name() string {
	return fp.name
}

// Description returns the description of the parameter
func (fp FeatureParameter) Description() string {
	return fp.description
}

// HasDefaultValue tells if the parameter has a default value
func (fp FeatureParameter) HasDefaultValue() bool {
	return fp.hasDefaultValue
}

// DefaultValue returns the default value of the parameter
func (fp FeatureParameter) DefaultValue() (string, bool) {
	if fp.hasDefaultValue {
		return fp.defaultValue, true
	}

	return "", false
}

// HasValueControl tells if the parameter has a value control
func (fp FeatureParameter) HasValueControl() bool {
	return fp.hasValueControl
}

// ValueControlCode returns the bash code to control the value
func (fp FeatureParameter) ValueControlCode() (string, bool) {
	if fp.hasValueControl {
		return fp.valueControlCode, true
	}

	return "", false
}

// ConditionedFeatureParameter describes a Feature prepared for use on a Target
type ConditionedFeatureParameter struct {
	FeatureParameter
	currentValue string // contains overloaded value of the parameter (ie provided by CLI)
	controlled   bool   // tells if the content has been controlled (ie script to define the value has been called
}

// NewConditionedFeatureParameter creates an instance of ConditionedFeatureParameter from FeatureParameter and sets the current value
func NewConditionedFeatureParameter(parameter FeatureParameter, value *string) (ConditionedFeatureParameter, fail.Error) {
	out := ConditionedFeatureParameter{
		FeatureParameter: parameter,
	}
	if value == nil {
		if !parameter.HasDefaultValue() {
			return ConditionedFeatureParameter{}, fail.InvalidRequestError("missing value for parameter '%s'", parameter.name)
		}

		out.currentValue, _ = parameter.DefaultValue()
	} else {
		out.currentValue = *value
	}
	return out, nil
}

// Value returns the current value of the parameter
func (cfp ConditionedFeatureParameter) Value() string {
	return cfp.currentValue
}

type ConditionedFeatureParameters map[string]ConditionedFeatureParameter

// ToMap converts a ConditionedFeatureParameters to a data.Map (to be used in template)
func (cfp ConditionedFeatureParameters) ToMap() data.Map[string, any] {
	out := data.NewMap[string, any]()
	for k, v := range cfp {
		out[k] = v.Value()
	}
	return out
}
