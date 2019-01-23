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

package client

import (
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/utils"
)

// host is the broker client part handling hosts
type template struct {
	// session is not used currently
	session *Session
}

// List return the list of availble templates on the current tenant
func (t *template) List(all bool, timeout time.Duration) (*pb.TemplateList, error) {
	t.session.Connect()
	defer t.session.Disconnect()
	service := pb.NewTemplateServiceClient(t.session.connection)
	ctx := utils.GetCancelContext()
	return service.List(ctx, &pb.TemplateListRequest{All: all})

}
