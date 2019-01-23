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

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/server/handlers"
	conv "github.com/CS-SI/SafeScale/broker/utils"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// TemplateHandler exists to ease integration tests
var TemplateHandler = handlers.NewTemplateHandler

// broker template list --all=false

// TemplateListener host service server grpc
type TemplateListener struct{}

// List available templates
func (s *TemplateListener) List(ctx context.Context, in *pb.TemplateListRequest) (*pb.TemplateList, error) {
	log.Printf("Template List called")

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't list templates: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't list templates: no tenant set")
	}

	handler := TemplateHandler(tenant.Service)
	templates, err := handler.List(ctx, in.GetAll())
	if err != nil {
		return nil, err
	}

	// Map model.Host to pb.Host
	var pbTemplates []*pb.HostTemplate
	for _, template := range templates {
		pbTemplates = append(pbTemplates, conv.ToPBHostTemplate(&template))
	}
	rv := &pb.TemplateList{Templates: pbTemplates}
	return rv, nil
}
