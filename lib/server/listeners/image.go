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

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// ImageHandler ...
var ImageHandler = handlers.NewImageHandler

// safescale image list --all=false

// ImageListener image service server grpc
type ImageListener struct{}

// List available images
func (s *ImageListener) List(ctx context.Context, in *pb.ImageListRequest) (il *pb.ImageList, err error) {
	if s == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Message())
	}

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "List Images"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		logrus.Info("Can't list images: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot list images: no tenant set")
	}

	handler := ImageHandler(currentTenant.Service)
	images, err := handler.List(ctx, in.GetAll())
	if err != nil {
		return nil, status.Errorf(codes.Internal, getUserMessage(err))
	}

	// Map resources.Image to pb.Image
	var pbImages []*pb.Image
	for _, image := range images {
		pbImages = append(pbImages, srvutils.ToPBImage(&image))
	}
	rv := &pb.ImageList{Images: pbImages}
	return rv, nil
}
