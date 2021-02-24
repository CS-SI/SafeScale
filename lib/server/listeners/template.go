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

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// safescale template list --all=false

// TemplateListener host service server grpc
type TemplateListener struct{}

// List available templates
func (s *TemplateListener) List(ctx context.Context, in *protocol.TemplateListRequest) (tl *protocol.TemplateList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list templates")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "template list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	all := in.GetAll()
	tracer := debug.NewTracer(job.GetTask(), true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	templates, xerr := job.GetService().ListTemplates(all)
	if xerr != nil {
		return nil, xerr
	}

	// Build response mapping resources.IPAddress to protocol.IPAddress
	var pbTemplates []*protocol.HostTemplate
	for _, template := range templates {
		pbTemplates = append(pbTemplates, converters.HostTemplateFromAbstractToProtocol(template))
	}
	rv := &protocol.TemplateList{Templates: pbTemplates}
	return rv, nil
}

// Match lists templates that match the sizing
func (s *TemplateListener) Match(ctx context.Context, in *protocol.TemplateMatchRequest) (tl *protocol.TemplateList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list templates")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "template match")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()

	sizing := in.GetSizing()
	tracer := debug.NewTracer(task, true, "%s", sizing).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	ahsr, _, xerr := converters.HostSizingRequirementsFromStringToAbstract(sizing)
	if xerr != nil {
		return nil, xerr
	}

	templates, xerr := job.GetService().ListTemplatesBySizing(*ahsr, false)
	if xerr != nil {
		return nil, xerr
	}

	var pbTemplates []*protocol.HostTemplate
	for _, template := range templates {
		pbTemplates = append(pbTemplates, converters.HostTemplateFromAbstractToProtocol(*template))
	}
	rv := &protocol.TemplateList{Templates: pbTemplates}
	return rv, nil
}
