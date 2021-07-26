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

package listeners

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	// "github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"

	"github.com/CS-SI/SafeScale/lib/protocol"
	clusterfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/cluster"
	featurefactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/feature"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// FeatureListener feature service server grpc
type FeatureListener struct{}

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
	//	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
	//		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	//	}
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

	job, err := PrepareJob(ctx, in.GetTargetRef().GetTenantId(), "/features/list")
	if err != nil {
		return nil, err
	}
	defer job.Close()
	task := job.Task()
	svc := job.Service()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.feature"), "(%s, %s)", targetType, targetRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
	case protocol.FeatureTargetType_FT_CLUSTER:
		rc, xerr := clusterfactory.Load(svc, targetRef)
		if xerr != nil {
			return empty, xerr
		}

		list, xerr := rc.ListInstalledFeatures(task.Context())
		if xerr != nil {
			return empty, xerr
		}

		return converters.FeatureSliceFromResourceToProtocol(list), nil
	}

	// Should not reach this
	return empty, fail.Wrap(fail.InconsistentError("reach theoretically unreachable point"), "cannot list features")
}

// Check ...
func (s *FeatureListener) Check(ctx context.Context, in *protocol.FeatureActionRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	//	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
	//		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	//	}
	targetType := in.GetTargetType()
	if targetType != protocol.FeatureTargetType_FT_HOST && targetType != protocol.FeatureTargetType_FT_CLUSTER {
		return empty, fail.InvalidParameterError("in.TargetType", "invalid value '%d'", targetType)
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
	task := job.Task()
	svc := job.Service()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.feature"), "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer func() {
		if err != nil {
			switch err.(type) {
			case *fail.ErrNotFound:
			default:
				fail.OnExitLogError(err, tracer.TraceMessage())
			}
		}
	}()

	feat, xerr := featurefactory.New(svc, featureName)
	if xerr != nil {
		return empty, xerr
	}

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
		rh, xerr := hostfactory.Load(svc, targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Check(task.Context(), rh, featureVariables, featureSettings)
		if xerr != nil {
			return empty, fail.Wrap(xerr, "cannot check feature")
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.NotFoundError("feature '%s' not found on Host '%s'", featureName, rh.GetName())
	case protocol.FeatureTargetType_FT_CLUSTER:
		rc, xerr := clusterfactory.Load(svc, targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Check(task.Context(), rc, featureVariables, featureSettings)
		if xerr != nil {
			return empty, fail.Wrap(xerr, "cannot check feature")
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.NotFoundError("feature '%s' not found on Cluster %s (missing on %s)", featureName, targetRefLabel, strings.Join(results.Keys(), ", "))
	}

	// Should not reach this
	return empty, fail.Wrap(fail.InconsistentError("reach theoretically unreachable point"), "cannot check feature")
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
	//	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
	//		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	//	}
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
	task := job.Task()
	svc := job.Service()

	tracer := debug.NewTracer(job.Task(), true /*tracing.ShouldTrace("listeners.feature")*/, "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	feat, xerr := featurefactory.New(svc, featureName)
	if xerr != nil {
		return empty, xerr
	}

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
		rh, xerr := hostfactory.Load(svc, targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Add(task.Context(), rh, featureVariables, featureSettings)
		if xerr != nil {
			return empty, xerr
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.ExecutionError(nil, "failed to add feature '%s' to Host '%s' (%s)", featureName, targetRefLabel, results.AllErrorMessages())
	case protocol.FeatureTargetType_FT_CLUSTER:
		rc, xerr := clusterfactory.Load(svc, targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Add(task.Context(), rc, featureVariables, featureSettings)
		if xerr != nil {
			return empty, xerr
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.ExecutionError(nil, "failed to add feature '%s' to Cluster '%s' (%s)", featureName, targetRefLabel, results.AllErrorMessages())
	}

	// Should not reach this
	return empty, fail.Wrap(fail.InconsistentError("reach theoretically unreachable point"), "cannot check feature")
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
	//	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
	//		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	//	}
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
	task := job.Task()
	svc := job.Service()

	tracer := debug.NewTracer(task, true /*tracing.ShouldTrace("listeners.feature")*/, "(%d, %s, %s)", targetType, targetRefLabel, featureName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	feat, xerr := featurefactory.New(svc, featureName)
	if xerr != nil {
		return empty, xerr
	}

	switch targetType {
	case protocol.FeatureTargetType_FT_HOST:
		rh, xerr := hostfactory.Load(svc, targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Remove(task.Context(), rh, featureVariables, featureSettings)
		if xerr != nil {
			return empty, fail.Wrap(xerr, "cannot remove feature")
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.ExecutionError(nil, "failed to remove feature '%s' from Host '%s' (%s)", featureName, targetRefLabel, results.AllErrorMessages())
	case protocol.FeatureTargetType_FT_CLUSTER:
		rc, xerr := clusterfactory.Load(svc, targetRef)
		if xerr != nil {
			return empty, xerr
		}

		results, xerr := feat.Remove(task.Context(), rc, featureVariables, featureSettings)
		if xerr != nil {
			return empty, fail.Wrap(xerr, "cannot remove feature")
		}
		if results.Successful() {
			return empty, nil
		}
		return empty, fail.ExecutionError(nil, "failed to remove feature '%s' from Cluster '%s' (%s)", featureName, targetRefLabel, results.AllErrorMessages())
	}

	// Should not reach this
	return empty, fail.Wrap(fail.InconsistentError("reach theoretically unreachable point"), "cannot remove feature")
}
