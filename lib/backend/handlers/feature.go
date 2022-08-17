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

package handlers

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	clusterfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/cluster"
	featurefactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/feature"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.FeatureHandler -o mocks/mock_feature.go

// FeatureHandler interface defines the methods available to handle Features
type FeatureHandler interface {
	Add(featuretargettype.Enum, string, string, data.Map, resources.FeatureSettings) fail.Error
	Check(featuretargettype.Enum, string, string, data.Map, resources.FeatureSettings) fail.Error
	Export(featuretargettype.Enum, string, string, bool) (*protocol.FeatureExportResponse, fail.Error)
	Inspect(featuretargettype.Enum, string, string) (resources.Feature, fail.Error)
	List(featuretargettype.Enum, string, bool) ([]resources.Feature, fail.Error)
	Remove(featuretargettype.Enum, string, string, data.Map, resources.FeatureSettings) fail.Error
}

// featureHandler is an implementation of FeatureHandler
type featureHandler struct {
	job server.Job
}

func NewFeatureHandler(job server.Job) FeatureHandler {
	return &featureHandler{job: job}
}

// List ...
// Note: returned []resources.Feature must be .Released by caller
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

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.feature"), "(%s)", targetType, targetRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	switch targetType {
	case featuretargettype.Host:
		hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
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
		clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
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
	}

	// Should not reach this
	return nil, fail.InconsistentError("reached theoretically unreachable point")
}

// Inspect ...
// Note: returned resources.Feature must be .Released() by the caller
func (handler *featureHandler) Inspect(targetType featuretargettype.Enum, targetRef, featureName string) (_ resources.Feature, ferr fail.Error) {
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
		return nil, fail.InvalidParameterCannotBeEmptyStringError("targetRef")
	}
	if featureName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("featureName")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.feature"), "(%s, %s, %s)", targetType.String(), targetRef, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	feat, xerr := featurefactory.New(handler.job.Context(), handler.job.Service(), featureName)
	if xerr != nil {
		return nil, xerr
	}
	if valid.IsNil(feat) {
		return nil, fail.InconsistentError("invalid feature %s", featureName)
	}

	switch targetType {
	case featuretargettype.Host:
		_ /*hostInstance*/, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
		if xerr != nil {
			return nil, xerr
		}

		return nil, fail.NotImplementedError()

	case featuretargettype.Cluster:
		_ /*clusterInstance*/, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
		if xerr != nil {
			return nil, xerr
		}

		return nil, fail.NotImplementedError()

	default:
		return nil, fail.InvalidParameterError("targetType", "invalid value %d", targetType)
	}
}

// Export exports the content of the feature file
func (handler *featureHandler) Export(targetType featuretargettype.Enum, targetRef, featureName string, embedded bool) (_ *protocol.FeatureExportResponse, ferr fail.Error) {
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
		return nil, fail.InvalidParameterCannotBeEmptyStringError("targetRef")
	}
	if featureName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("featureName")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.feature"), "(%s, %s, %s)", targetType.String(), targetRef, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	var (
		feat resources.Feature
		xerr fail.Error
	)
	if embedded {
		feat, xerr = featurefactory.NewEmbedded(handler.job.Context(), handler.job.Service(), featureName)
	} else {
		feat, xerr = featurefactory.New(handler.job.Context(), handler.job.Service(), featureName)
	}
	if xerr != nil {
		return nil, xerr
	}
	if valid.IsNil(feat) {
		return nil, fail.InconsistentError("invalid feature: %s", featureName)
	}

	switch targetType {
	case featuretargettype.Host:
		_ /*hostInstance*/, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
		if xerr != nil {
			return nil, xerr
		}

		return nil, fail.NotImplementedError()

	case featuretargettype.Cluster:
		_ /*clusterInstance*/, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
		if xerr != nil {
			return nil, xerr
		}

		return nil, fail.NotImplementedError()

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

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.feature"), "(%s, %s, %s)", targetType.String(), targetRef, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	feat, xerr := featurefactory.New(handler.job.Context(), handler.job.Service(), featureName)
	if xerr != nil {
		return xerr
	}

	switch targetType {
	case featuretargettype.Host:
		hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
		if xerr != nil {
			return xerr
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
		clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
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

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.feature"), "(%s, %s, %s)", targetType.String(), targetRef, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	feat, xerr := featurefactory.New(handler.job.Context(), handler.job.Service(), featureName)
	if xerr != nil {
		return xerr
	}

	switch targetType {
	case featuretargettype.Host:
		hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
		if xerr != nil {
			return xerr
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
		clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
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

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.feature"), "(%s, %s, %s)", targetType.String(), targetRef, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	feat, xerr := featurefactory.New(handler.job.Context(), handler.job.Service(), featureName)
	if xerr != nil {
		return xerr
	}

	switch targetType {
	case featuretargettype.Host:
		hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
		if xerr != nil {
			return xerr
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
		clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), targetRef)
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
