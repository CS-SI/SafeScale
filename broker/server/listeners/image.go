/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/server/handlers"
	"github.com/CS-SI/SafeScale/broker/utils"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	log "github.com/sirupsen/logrus"
)

// ImageHandler ...
var ImageHandler = handlers.NewImageHandler

// broker image list --all=false

//ImageListener image service server grpc
type ImageListener struct{}

// List available images
func (s *ImageListener) List(ctx context.Context, in *pb.ImageListRequest) (*pb.ImageList, error) {
	log.Printf("List images called")

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "List Images"); err != nil {
		return nil, fmt.Errorf("Failed to register the process : %s", err.Error())
	}
	defer utils.ProcessDeregister(ctx)

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't list images: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't list images: no tenant set")
	}

	handler := ImageHandler(currentTenant.Service)
	images, err := handler.List(ctx, in.GetAll())
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}

	// Map resources.Image to pb.Image
	var pbImages []*pb.Image
	for _, image := range images {
		pbImages = append(pbImages, conv.ToPBImage(&image))
	}
	rv := &pb.ImageList{Images: pbImages}
	return rv, nil
}
