/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	conv "github.com/CS-SI/SafeScale/lib/server/utils"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// TemplateHandler exists to ease integration tests
var TemplateHandler = handlers.NewTemplateHandler

// safescale template list --all=false

// TemplateListener host service server grpc
type TemplateListener struct{}

// List available templates
func (s *TemplateListener) List(ctx context.Context, in *pb.TemplateListRequest) (tl *pb.TemplateList, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	all := in.GetAll()

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Templates List"); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot list templates: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := TemplateHandler(tenant.Service)
	templates, err := handler.List(ctx, all)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot list templates").ToGRPCStatus()
	}

	// Map resources.Host to pb.Host
	var pbTemplates []*pb.HostTemplate
	for _, template := range templates {
		pbTemplates = append(pbTemplates, conv.ToPBHostTemplate(&template))
	}
	rv := &pb.TemplateList{Templates: pbTemplates}
	return rv, nil
}
