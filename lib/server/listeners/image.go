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

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// safescale image list --all=false

// ImageListener image service server grpc
type ImageListener struct {
	protocol.UnimplementedImageServiceServer
}

// List available images
func (s *ImageListener) List(inctx context.Context, in *protocol.ImageListRequest) (_ *protocol.ImageList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list image")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	job, err := PrepareJob(inctx, in.GetTenantId(), "/images/list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewImageHandler(job)
	images, xerr := handler.List(in.GetAll())
	if xerr != nil {
		return nil, xerr
	}

	// Build response mapping abstract.Image to protocol.Image
	pbImages := make([]*protocol.Image, len(images))
	for k, image := range images {
		pbImages[k] = converters.ImageFromAbstractToProtocol(image)
	}
	out := &protocol.ImageList{Images: pbImages}
	return out, nil
}
