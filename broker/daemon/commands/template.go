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
	"log"

	pb "github.com/CS-SI/SafeScale/broker"
	services "github.com/CS-SI/SafeScale/broker/daemon/services"
	conv "github.com/CS-SI/SafeScale/broker/utils"
)

// broker template list --all=false

//TempalteServiceServer host service server grpc
type TempalteServiceServer struct{}

// List available templates
func (s *TempalteServiceServer) List(ctx context.Context, in *pb.TemplateListRequest) (*pb.TemplateList, error) {
	log.Printf("Template List called")

	if GetCurrentTenant() == nil {
		return nil, fmt.Errorf("No tenant set")
	}

	service := services.NewTemplateService(currentTenant.Client)

	templates, err := service.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	var pbTempaltes []*pb.HostTemplate

	// Map api.Host to pb.Host
	for _, template := range templates {
		pbTempaltes = append(pbTempaltes, conv.ToPBHostTemplate(&template))
	}
	rv := &pb.TemplateList{Templates: pbTempaltes}
	log.Printf("End ListTemplates")
	return rv, nil
}
