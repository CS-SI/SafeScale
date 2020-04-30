/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// safescale template list --all=false

// TemplateListener host service server grpc
type TemplateListener struct{}

// ErrorList available templates
func (s *TemplateListener) List(ctx context.Context, in *protocol.TemplateListRequest) (tl *protocol.TemplateList, err error) {
	defer func() {
		if err != nil {
			err = fail.Wrap(err, "cannot list templates").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "template list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()
	tracer := concurrency.NewTracer(job.SafeGetTask(), true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewTemplateHandler(job)
	templates, err := handler.List(all)
	if err != nil {
		return nil, err
	}

	// Build response mapping resources.Host to protocol.Host
	var pbTemplates []*protocol.HostTemplate
	for _, template := range templates {
		pbTemplates = append(pbTemplates, converters.HostTemplateFromAbstractToProtocol(template))
	}
	rv := &protocol.TemplateList{Templates: pbTemplates}
	return rv, nil
}
