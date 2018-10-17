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

package commands

import (
	"context"
	"fmt"
	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/daemon/services"
	conv "github.com/CS-SI/SafeScale/broker/utils"
	log "github.com/sirupsen/logrus"
)

// broker image list --all=false

//ImageServiceServer image service server grpc
type ImageServiceServer struct{}

// List available images
func (s *ImageServiceServer) List(ctx context.Context, in *pb.ImageListRequest) (*pb.ImageList, error) {
	log.Printf("List images called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("Cannot list images : No tenant set")
	}

	service := services.NewImageService(currentTenant.Client)

	images, err := service.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	var pbImages []*pb.Image

	// Map api.Image to pb.Image
	for _, image := range images {
		pbImages = append(pbImages, conv.ToPBImage(&image))
	}
	rv := &pb.ImageList{Images: pbImages}
	log.Printf("End List images")
	return rv, nil
}
