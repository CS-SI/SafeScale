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

package listeners

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	clusterfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/cluster"
	featurefactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/feature"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/host"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/server/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// FeatureListener feature service server grpc
type FeatureListener struct {
	protocol.UnimplementedFeatureServiceServer
}

// List ...
func (s *FeatureListener) List(ctx context.Context, in *protocol.FeatureListRequest) (_ *protocol.FeatureListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list features")
	defer fail.OnPanic(&err)

	empty := &protocol.FeatureListResponse{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}

	targetType := in.GetTargetType()
	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
	case protocol.FeatureTargetType_FT_CLUSTER:
	default:
		return empty, fail.InvalidParameterError("in.TargetType", "invalid value (%d)", targetType)
	}
	targetRef, targetRefLabel := srvutils.GetReference(in.GetTargetRef())
	if targetRef == "" {
		return empty, fail.InvalidParameterError("in.TargetRef", "neither Name nor ID fields are provided")
	}

	job, xerr := PrepareJob(ctx, in.GetTargetRef().GetTenantId(), "/features/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.feature"), "(%s, %s)", targetType, targetRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
		hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return empty, xerr
		}

		var list []resources.Feature
		if in.GetInstalledOnly() {
			list, xerr = hostInstance.ListInstalledFeatures(job.Context())
		} else {
			list, xerr = hostInstance.ListEligibleFeatures(job.Context())
		}
		if xerr != nil {
			return empty, xerr
		}

		return converters.FeatureSliceFromResourceToProtocol(ctx, list), nil

	case protocol.FeatureTargetType_FT_CLUSTER:
		clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return empty, xerr
		}

		var list []resources.Feature
		if in.GetInstalledOnly() {
			list, xerr = clusterInstance.ListInstalledFeatures(job.Context())
		} else {
			list, xerr = clusterInstance.ListEligibleFeatures(job.Context())
		}
		if xerr != nil {
			return empty, xerr
		}

		return converters.FeatureSliceFromResourceToProtocol(ctx, list), nil
	}

	// Should not reach this
	return empty, fail.Wrap(fail.InconsistentError("reached theoretically unreachable point"), "cannot list features")
}

// Inspect ...
func (s *FeatureListener) Inspect(ctx context.Context, in *protocol.FeatureDetailRequest) (_ *protocol.FeatureDetailResponse, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(&ferr)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	targetType := in.GetTargetType()
	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
	case protocol.FeatureTargetType_FT_CLUSTER:
	default:
		return nil, fail.InvalidParameterError("in.TargetType", "invalid value (%d)", targetType)
	}
	targetRef, targetRefLabel := srvutils.GetReference(in.GetTargetRef())
	if targetRef == "" {
		return nil, fail.InvalidRequestError("target reference is missing")
	}
	featureName := in.GetName()

	job, err := PrepareJob(ctx, in.GetTargetRef().GetTenantId(), fmt.Sprintf("/feature/%s/check/%s/%s", featureName, targetType, targetRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.feature"), "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer func() {
		if ferr != nil {
			switch ferr.(type) {
			case *fail.ErrNotFound:
			default:
				fail.OnExitLogError(ferr, tracer.TraceMessage())
			}
		}
	}()

	feat, xerr := featurefactory.New(job.Context(), job.Service(), featureName)
	if xerr != nil {
		return nil, xerr
	}
	if valid.IsNil(feat) {
		return nil, fail.InconsistentError("invalid feature %s", featureName)
	}

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
		_, xerr := hostfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return nil, xerr
		}

		return nil, fail.NotImplementedError()

	case protocol.FeatureTargetType_FT_CLUSTER:
		_, xerr := clusterfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return nil, xerr
		}

		return nil, fail.NotImplementedError()
	}

	// Should not reach this
	return nil, fail.Wrap(fail.InconsistentError("reached theoretically unreachable point"), "cannot inspect feature")
}

// Export exports the content of the feature file
func (s *FeatureListener) Export(ctx context.Context, in *protocol.FeatureDetailRequest) (_ *protocol.FeatureExportResponse, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(&ferr)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	targetType := in.GetTargetType()
	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
	case protocol.FeatureTargetType_FT_CLUSTER:
	default:
		return nil, fail.InvalidParameterError("in.TargetType", "invalid value (%d)", targetType)
	}
	targetRef, targetRefLabel := srvutils.GetReference(in.GetTargetRef())
	if targetRef == "" {
		return nil, fail.InvalidRequestError("target reference is missing")
	}
	featureName := in.GetName()

	job, xerr := PrepareJob(ctx, in.GetTargetRef().GetTenantId(), fmt.Sprintf("/feature/%s/check/%s/%s", featureName, targetType, targetRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.feature"), "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer func() {
		if ferr != nil {
			switch ferr.(type) {
			case *fail.ErrNotFound:
			default:
				fail.OnExitLogError(ferr, tracer.TraceMessage())
			}
		}
	}()

	var feat resources.Feature
	if in.GetEmbedded() {
		feat, xerr = featurefactory.NewEmbedded(job.Context(), job.Service(), featureName)
	} else {
		feat, xerr = featurefactory.New(job.Context(), job.Service(), featureName)
	}
	if xerr != nil {
		return nil, xerr
	}
	if valid.IsNil(feat) {
		return nil, fail.InconsistentError("invalid feature: %s", featureName)
	}

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
		_, xerr := hostfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return nil, xerr
		}

		return nil, fail.NotImplementedError()

	case protocol.FeatureTargetType_FT_CLUSTER:
		_, xerr := clusterfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return nil, xerr
		}

		return nil, fail.NotImplementedError()
	}

	// Should not reach this
	return nil, fail.Wrap(fail.InconsistentError("reached theoretically unreachable point"), "cannot check feature")
}

// Check checks if a feature installed on target
func (s *FeatureListener) Check(ctx context.Context, in *protocol.FeatureActionRequest) (empty *googleprotobuf.Empty, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(&ferr)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	targetType := in.GetTargetType()
	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
	case protocol.FeatureTargetType_FT_CLUSTER:
	default:
		return empty, fail.InvalidParameterError("in.TargetType", "invalid value (%d)", targetType)
	}
	targetRef, targetRefLabel := srvutils.GetReference(in.GetTargetRef())
	if targetRef == "" {
		return empty, fail.InvalidRequestError("target reference is missing")
	}
	featureName := in.GetName()
	featureVariables, xerr := convertVariablesToDataMap(in.GetVariables())
	if xerr != nil {
		return empty, fail.Wrap(xerr, "failed to check feature")
	}
	featureSettings := converters.FeatureSettingsFromProtocolToResource(in.GetSettings())

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/feature/%s/check/%s/%s", featureName, targetType, targetRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.feature"), "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer func() {
		if ferr != nil {
			switch ferr.(type) {
			case *fail.ErrNotFound:
			default:
				fail.OnExitLogError(ferr, tracer.TraceMessage())
			}
		}
	}()

	feat, xerr := featurefactory.New(job.Context(), job.Service(), featureName)
	if xerr != nil {
		return empty, xerr
	}

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
		hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Check(job.Context(), hostInstance, featureVariables, featureSettings)
		if xerr != nil {
			return empty, fail.Wrap(xerr, "cannot check feature")
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.NotFoundError("feature '%s' not found on Host '%s'", featureName, hostInstance.GetName())

	case protocol.FeatureTargetType_FT_CLUSTER:
		clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Check(job.Context(), clusterInstance, featureVariables, featureSettings)
		if xerr != nil {
			return empty, fail.Wrap(xerr, "cannot check feature")
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.NotFoundError("feature '%s' not found on Cluster %s (missing on %s)", featureName, targetRefLabel, strings.Join(results.Keys(), ", "))
	}

	// Should not reach this
	return empty, fail.Wrap(fail.InconsistentError("reached theoretically unreachable point"), "cannot check feature")
}

func convertVariablesToDataMap(in map[string]string) (data.Map, fail.Error) {
	var out data.Map
	if len(in) > 0 {
		jsoned, err := json.Marshal(in)
		if err != nil {
			return data.Map{}, fail.Wrap(err, "failed to check feature: failed to convert variables to json")
		}
		if err = json.Unmarshal(jsoned, &out); err != nil {
			return data.Map{}, fail.Wrap(err, "failed to check feature: failed to convert variables")
		}
	}
	return out, nil
}

// Add ...
func (s *FeatureListener) Add(ctx context.Context, in *protocol.FeatureActionRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	targetType := in.GetTargetType()
	targetRef, targetRefLabel := srvutils.GetReference(in.GetTargetRef())
	if targetRef == "" {
		return empty, fail.InvalidRequestError("target reference is missing")
	}
	featureName := in.GetName()
	featureVariables, xerr := convertVariablesToDataMap(in.GetVariables())
	if xerr != nil {
		return empty, fail.Wrap(xerr, "failed to add feature")
	}
	featureSettings := converters.FeatureSettingsFromProtocolToResource(in.GetSettings())

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/feature/%s/add/%s/%s", featureName, targetType, targetRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), true /*tracing.ShouldTrace("listeners.feature")*/, "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	feat, xerr := featurefactory.New(job.Context(), job.Service(), featureName)
	if xerr != nil {
		return empty, xerr
	}

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
		hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Add(job.Context(), hostInstance, featureVariables, featureSettings)
		if xerr != nil {
			return empty, xerr
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.ExecutionError(nil, "failed to add feature '%s' to Host '%s' (%s)", featureName, targetRefLabel, results.AllErrorMessages())

	case protocol.FeatureTargetType_FT_CLUSTER:
		clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Add(job.Context(), clusterInstance, featureVariables, featureSettings)
		if xerr != nil {
			return empty, xerr
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.ExecutionError(nil, "failed to add feature '%s' to Cluster '%s' (%s)", featureName, targetRefLabel, results.AllErrorMessages())
	}

	// Should not reach this
	return empty, fail.Wrap(fail.InconsistentError("reached theoretically unreachable point"), "cannot check feature")
}

// Remove uninstalls a Feature
func (s *FeatureListener) Remove(ctx context.Context, in *protocol.FeatureActionRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	targetType := in.GetTargetType()
	targetRef, targetRefLabel := srvutils.GetReference(in.GetTargetRef())
	if targetRef == "" {
		return empty, fail.InvalidRequestError("target reference is missing")
	}
	featureName := in.GetName()
	featureVariables, xerr := convertVariablesToDataMap(in.GetVariables())
	if xerr != nil {
		return empty, fail.Wrap(xerr, "failed to check feature")
	}
	featureSettings := converters.FeatureSettingsFromProtocolToResource(in.GetSettings())

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/feature/%s/remove/%s/%s", featureName, targetType, targetRef))
	if err != nil {
		return empty, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), true /*tracing.ShouldTrace("listeners.feature")*/, "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	feat, xerr := featurefactory.New(job.Context(), job.Service(), featureName)
	if xerr != nil {
		return empty, xerr
	}

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
		hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Remove(job.Context(), hostInstance, featureVariables, featureSettings)
		if xerr != nil {
			return empty, fail.Wrap(xerr, "cannot remove feature")
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.ExecutionError(nil, "failed to remove feature '%s' from Host '%s' (%s)", featureName, targetRefLabel, results.AllErrorMessages())

	case protocol.FeatureTargetType_FT_CLUSTER:
		clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Remove(job.Context(), clusterInstance, featureVariables, featureSettings)
		if xerr != nil {
			return empty, fail.Wrap(xerr, "cannot remove feature")
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.ExecutionError(nil, "failed to remove feature '%s' from Cluster '%s' (%s)", featureName, targetRefLabel, results.AllErrorMessages())
	}

	// Should not reach this
	return empty, fail.Wrap(fail.InconsistentError("reached theoretically unreachable point"), "cannot remove feature")
}
