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

// ImageHandler ...
var ImageHandler = handlers.NewImageHandler

// safescale image list --all=false

//ImageListener image service server grpc
type ImageListener struct{}

// List available images
func (s *ImageListener) List(ctx context.Context, in *pb.ImageListRequest) (_ *pb.ImageList, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// FIXME: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "List Images"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot list images: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := ImageHandler(currentTenant.Service)
	images, err := handler.List(ctx, in.GetAll())
	if err != nil {
		return nil, scerr.Wrap(err, "cannot list image").ToGRPCStatus()
	}

	// Map resources.Image to pb.Image
	var pbImages []*pb.Image
	for _, image := range images {
		pbImages = append(pbImages, conv.ToPBImage(&image))
	}
	rv := &pb.ImageList{Images: pbImages}
	return rv, nil
}
