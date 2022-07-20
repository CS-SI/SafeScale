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

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/server/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
)

// FeatureListener feature service server grpc
type FeatureListener struct {
	protocol.UnimplementedFeatureServiceServer
}

// List ...
func (s *FeatureListener) List(inctx context.Context, in *protocol.FeatureListRequest) (_ *protocol.FeatureListResponse, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot list Features")
	defer fail.OnPanic(&ferr)

	empty := &protocol.FeatureListResponse{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil").ToGRPCStatus()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}

	targetType, xerr := convertTargetType(in.GetTargetType())
	if xerr != nil {
		return nil, xerr
	}

	targetRef, targetRefLabel := srvutils.GetReference(in.GetTargetRef())
	if targetRef == "" {
		return empty, fail.InvalidParameterError("in.TargetRef", "neither Name nor ID fields are provided")
	}

	job, xerr := PrepareJob(inctx, in.GetTargetRef().GetTenantId(), "/features/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.feature"), "(%s, %s)", in.GetTargetType(), targetRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	handler := handlers.NewFeatureHandler(job)
	list, xerr := handler.List(targetType, targetRef, in.GetInstalledOnly())
	if xerr != nil {
		return empty, xerr
	}

	return converters.FeatureSliceFromResourceToProtocol(ctx, list), nil
}

func convertTargetType(in protocol.FeatureTargetType) (featuretargettype.Enum, fail.Error) {
	var targetType featuretargettype.Enum
	switch in {
	case protocol.FeatureTargetType_FT_HOST:
		targetType = featuretargettype.Host
	case protocol.FeatureTargetType_FT_CLUSTER:
		targetType = featuretargettype.Cluster
	default:
		return featuretargettype.Unknown, fail.InvalidParameterError("in", "invalid value %d", in)
	}
	return targetType, nil
}

// Inspect ...
func (s *FeatureListener) Inspect(inctx context.Context, in *protocol.FeatureDetailRequest) (_ *protocol.FeatureDetailResponse, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot inspect Feature")
	defer fail.OnPanic(&ferr)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	targetType, xerr := convertTargetType(in.GetTargetType())
	if xerr != nil {
		return nil, xerr
	}

	targetRef, targetRefLabel := srvutils.GetReference(in.GetTargetRef())
	if targetRef == "" {
		return nil, fail.InvalidRequestError("target reference is missing")
	}

	featureName := in.GetName()
	if featureName == "" {
		return nil, fail.InvalidRequestError("feature name is missing")
	}

	job, err := PrepareJob(inctx, in.GetTargetRef().GetTenantId(), fmt.Sprintf("/feature/%s/check/%s/%s", featureName, targetType, targetRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.feature"), "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, ferr, tracer.TraceMessage())

	handler := handlers.NewFeatureHandler(job)
	feat, xerr := handler.Inspect(targetType, targetRef, featureName)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: not implemented for now, no way to fill protocol.FeatureDetailsResponse from feat...
	_ = feat
	return nil, fail.NotImplementedError()
}

// Export exports the content of the feature file
func (s *FeatureListener) Export(inctx context.Context, in *protocol.FeatureDetailRequest) (_ *protocol.FeatureExportResponse, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot export Feature")
	defer fail.OnPanic(&ferr)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	targetType, xerr := convertTargetType(in.GetTargetType())
	if xerr != nil {
		return nil, xerr
	}

	targetRef, targetRefLabel := srvutils.GetReference(in.GetTargetRef())
	if targetRef == "" {
		return nil, fail.InvalidRequestError("target reference is missing")
	}
	featureName := in.GetName()

	job, xerr := PrepareJob(inctx, in.GetTargetRef().GetTenantId(), fmt.Sprintf("/feature/%s/check/%s/%s", featureName, targetType, targetRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.feature"), "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, ferr, tracer.TraceMessage())

	handler := handlers.NewFeatureHandler(job)
	return handler.Export(targetType, targetRef, featureName, in.GetEmbedded())
}

// Check checks if a feature installed on target
func (s *FeatureListener) Check(inctx context.Context, in *protocol.FeatureActionRequest) (empty *googleprotobuf.Empty, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer func() {
		ferr = debug.InjectPlannedError(ferr)
		if ferr != nil {
			switch cerr := ferr.(type) {
			case *fail.ErrNotFound:
				// Do not wrap *fail.ErrNotFound if it means "Feature not installed"
				if val, found := cerr.Annotation("not_installed"); !found || !val.(bool) {
					fail.OnExitWrapError(inctx, &ferr, "cannot check Feature")
				}
			default:
				fail.OnExitWrapError(inctx, &ferr, "cannot check Feature")
			}
		}
	}()
	defer fail.OnPanic(&ferr)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	targetType, xerr := convertTargetType(in.GetTargetType())
	if xerr != nil {
		return nil, xerr
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

	job, err := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/feature/%s/check/%s/%s", featureName, targetType, targetRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.feature"), "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer func() {
		ferr = debug.InjectPlannedError(ferr)
		if ferr != nil {
			switch ferr.(type) {
			case *fail.ErrNotFound:
			default:
				fail.OnExitLogError(ctx, ferr, tracer.TraceMessage())
			}
		}
	}()

	handler := handlers.NewFeatureHandler(job)
	xerr = handler.Check(targetType, targetRef, featureName, featureVariables, featureSettings)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return empty, fail.NotFoundError("failed to find Feature '%s' on %s %s", featureName, targetType.String(), targetRefLabel)
		default:
			return empty, xerr
		}
	}

	return empty, nil
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
func (s *FeatureListener) Add(inctx context.Context, in *protocol.FeatureActionRequest) (empty *googleprotobuf.Empty, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot add Feature")
	defer fail.OnPanic(&ferr)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	targetType, xerr := convertTargetType(in.GetTargetType())
	if xerr != nil {
		return nil, xerr
	}

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

	job, err := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/feature/%s/add/%s/%s", featureName, targetType, targetRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.feature"), "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	handler := handlers.NewFeatureHandler(job)
	xerr = handler.Add(targetType, targetRef, featureName, featureVariables, featureSettings)
	if xerr != nil {
		return empty, fail.Wrap(xerr, "failed to add feature '%s' to %s %s", featureName, targetType.String(), targetRefLabel)
	}

	return empty, nil
}

// Remove uninstalls a Feature
func (s *FeatureListener) Remove(inctx context.Context, in *protocol.FeatureActionRequest) (empty *googleprotobuf.Empty, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot remove Feature")
	defer fail.OnPanic(&ferr)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	targetType, xerr := convertTargetType(in.GetTargetType())
	if xerr != nil {
		return nil, xerr
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

	job, err := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/feature/%s/remove/%s/%s", featureName, targetType, targetRef))
	if err != nil {
		return empty, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.feature"), "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewFeatureHandler(job)
	xerr = handler.Remove(targetType, targetRef, featureName, featureVariables, featureSettings)
	if xerr != nil {
		return empty, fail.Wrap(xerr, "failed to remove Feature '%s' from %s %s", featureName, targetType.String(), targetRefLabel)
	}

	return empty, nil
}
