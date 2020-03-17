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
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// safescale image list --all=false

//ImageListener image service server grpc
type ImageListener struct{}

// List available images
func (s *ImageListener) List(ctx context.Context, in *protocol.ImageListRequest) (_ *protocol.ImageList, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot list image").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "image list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewImageHandler(job)
	images, err := handler.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	// Build response mapping abstract.Image to protocol.Image
	var pbImages []*protocol.Image
	for _, image := range images {
		pbImages = append(pbImages, converters.ImageFromAbstractToProtocol(&image))
	}
	rv := &protocol.ImageList{Images: pbImages}
	return rv, nil
}
