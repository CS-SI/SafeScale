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

package handlers

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	clusterfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/cluster"
	featurefactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/feature"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.FeatureHandler -o mocks/mock_feature.go

// FeatureHandler interface defines the methods available to handle Features
type FeatureHandler interface {
	Add(featuretargettype.Enum, string, string, data.Map, resources.FeatureSettings) fail.Error
	Check(featuretargettype.Enum, string, string, data.Map, resources.FeatureSettings) fail.Error
	List(featuretargettype.Enum, string, bool) ([]resources.Feature, fail.Error)
	Remove(featuretargettype.Enum, string, string, data.Map, resources.FeatureSettings) fail.Error
}

// featureHandler is an implementation of FeatureHandler
type featureHandler struct {
	job backend.Job
}

func NewFeatureHandler(job backend.Job) FeatureHandler {
	return &featureHandler{job: job}
}

// List ...
func (handler *featureHandler) List(targetType featuretargettype.Enum, targetRef string, installedOnly bool) (_ []resources.Feature, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if targetRef == "" {
		return nil, fail.InvalidParameterError("in.TargetRef", "neither Name nor ID fields are provided")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	switch targetType {
	case featuretargettype.Host:
		hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef, isTerraform)
		if xerr != nil {
			return nil, xerr
		}

		var list []resources.Feature
		if installedOnly {
			list, xerr = hostInstance.ListInstalledFeatures(handler.job.Context())
		} else {
			list, xerr = hostInstance.ListEligibleFeatures(handler.job.Context())
		}
		if xerr != nil {
			return nil, xerr
		}

		return list, nil

	case featuretargettype.Cluster:
		isTerraform := false
		pn, xerr := handler.job.Service().GetType()
		if xerr != nil {
			return nil, xerr
		}
		isTerraform = pn == "terraform"

		clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef, isTerraform)
		if xerr != nil {
			return nil, xerr
		}

		var list []resources.Feature
		if installedOnly {
			list, xerr = clusterInstance.ListInstalledFeatures(handler.job.Context())
		} else {
			list, xerr = clusterInstance.ListEligibleFeatures(handler.job.Context())
		}
		if xerr != nil {
			return nil, xerr
		}

		return list, nil
	default:
		return nil, fail.InvalidParameterError("targetType", "invalid value %d", targetType)
	}
}

// Check checks if a feature installed on target
func (handler *featureHandler) Check(targetType featuretargettype.Enum, targetRef, featureName string, variables data.Map, settings resources.FeatureSettings) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if targetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("targetRef")
	}
	if featureName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("featureName")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	feat, xerr := featurefactory.New(handler.job.Context(), handler.job.Service(), featureName) // BUG: Why do we want a factory that does NOT accept parameters ?
	if xerr != nil {
		return xerr
	}

	switch targetType {
	case featuretargettype.Host:
		hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef, isTerraform)
		if xerr != nil {
			return xerr
		}

		st, xerr := hostInstance.ForceGetState(handler.job.Context())
		if xerr != nil {
			return xerr
		}
		if st != hoststate.Started {
			return fail.NewError("Host MUST be in started state in order to check a feature")
		}

		results, xerr := feat.Check(handler.job.Context(), hostInstance, variables, settings)
		if xerr != nil {
			return xerr
		}
		if results.Successful() {
			return nil
		}

		// Feature not found on target, but we need to differentiate that case with the "Feature does not exist" case;
		// fail.Error annotation to the rescue
		xerr = fail.NotFoundError()
		_ = xerr.Annotate("not_installed", true)
		return xerr

	case featuretargettype.Cluster:
		isTerraform := false
		pn, xerr := handler.job.Service().GetType()
		if xerr != nil {
			return xerr
		}
		isTerraform = pn == "terraform"

		clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef, isTerraform)
		if xerr != nil {
			return xerr
		}

		results, xerr := feat.Check(handler.job.Context(), clusterInstance, variables, settings)
		if xerr != nil {
			return xerr
		}
		if results.Successful() {
			return nil
		}

		// Feature not found on target, but we need to differentiate that case with the "Feature does not exist" case;
		// fail.Error annotation to the rescue
		xerr = fail.NotFoundError()
		_ = xerr.Annotate("not_installed", true)
		return xerr

	default:
		return fail.InvalidParameterError("targetType", "invalid value %d", targetType)
	}
}

// func convertVariablesToDataMap(in map[string]string) (data.Map, fail.Error) {
// 	var out data.Map
// 	if len(in) > 0 {
// 		jsoned, err := json.Marshal(in)
// 		if err != nil {
// 			return data.Map{}, fail.Wrap(err, "failed to check feature: failed to convert variables to json")
// 		}
// 		if err = json.Unmarshal(jsoned, &out); err != nil {
// 			return data.Map{}, fail.Wrap(err, "failed to check feature: failed to convert variables")
// 		}
// 	}
// 	return out, nil
// }

// Add ...
func (handler *featureHandler) Add(targetType featuretargettype.Enum, targetRef, featureName string, variables data.Map, settings resources.FeatureSettings) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if targetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("targetRef")
	}
	if featureName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("featureName")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	feat, xerr := featurefactory.New(handler.job.Context(), handler.job.Service(), featureName) // BUG: Why do we want a factory that does NOT accept parameters ?
	if xerr != nil {
		return xerr
	}

	switch targetType {
	case featuretargettype.Host:
		hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef, isTerraform)
		if xerr != nil {
			return xerr
		}

		st, xerr := hostInstance.ForceGetState(handler.job.Context())
		if xerr != nil {
			return xerr
		}
		if st != hoststate.Started {
			return fail.NewError("Host MUST be in started state in order to add a feature")
		}

		results, xerr := feat.Add(handler.job.Context(), hostInstance, variables, settings)
		if xerr != nil {
			return xerr
		}
		if results.Successful() {
			return nil
		}
		return fail.ExecutionError(nil, results.AllErrorMessages())

	case featuretargettype.Cluster:
		isTerraform := false
		pn, xerr := handler.job.Service().GetType()
		if xerr != nil {
			return xerr
		}
		isTerraform = pn == "terraform"

		clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef, isTerraform)
		if xerr != nil {
			return xerr
		}

		results, xerr := feat.Add(handler.job.Context(), clusterInstance, variables, settings)
		if xerr != nil {
			return xerr
		}
		if results.Successful() {
			return nil
		}
		return fail.ExecutionError(nil, results.AllErrorMessages())

	default:
		return fail.InvalidParameterError("targetType", "invalid value %d", targetType)
	}
}

// Remove uninstalls a Feature
func (handler *featureHandler) Remove(targetType featuretargettype.Enum, targetRef, featureName string, variables data.Map, settings resources.FeatureSettings) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if targetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("targetRef")
	}
	if featureName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("featureName")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	feat, xerr := featurefactory.New(handler.job.Context(), handler.job.Service(), featureName) // BUG: Why do we want a factory that does NOT accept parameters ?
	if xerr != nil {
		return xerr
	}

	switch targetType {
	case featuretargettype.Host:
		hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef, isTerraform)
		if xerr != nil {
			return xerr
		}

		st, xerr := hostInstance.ForceGetState(handler.job.Context())
		if xerr != nil {
			return xerr
		}
		if st != hoststate.Started {
			return fail.NewError("Host MUST be in started state in order to remove a feature")
		}

		results, xerr := feat.Remove(handler.job.Context(), hostInstance, variables, settings)
		if xerr != nil {
			return xerr
		}
		if results.Successful() {
			return nil
		}
		return fail.ExecutionError(nil, results.AllErrorMessages())

	case featuretargettype.Cluster:
		isTerraform := false
		pn, xerr := handler.job.Service().GetType()
		if xerr != nil {
			return xerr
		}
		isTerraform = pn == "terraform"

		clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef, isTerraform)
		if xerr != nil {
			return xerr
		}

		results, xerr := feat.Remove(handler.job.Context(), clusterInstance, variables, settings)
		if xerr != nil {
			return xerr
		}
		if results.Successful() {
			return nil
		}
		return fail.ExecutionError(nil, results.AllErrorMessages())

	default:
		return fail.InvalidParameterError("targetType", "failed to handle type %d", targetType)
	}
}
