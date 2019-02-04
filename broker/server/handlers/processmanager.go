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

package handlers

import (
	"context"

	"github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"
)

// ProcessManagerAPI defines API to manipulate process
type ProcessManagerAPI interface {
	List(ctx context.Context) (map[string]string, error)
	Stop(ctx context.Context, uuid string)
}

// ProcessManagerHandler service
type ProcessManagerHandler struct {
	provider *providers.Service
}

// NewVolumeHandler creates a Volume service
func NewProcessManagerHandler(api *providers.Service) ProcessManagerAPI {
	return &ProcessManagerHandler{
		provider: api,
	}
}

// List returns the Running Process list
func (svc *ProcessManagerHandler) List(ctx context.Context) (map[string]string, error) {
	return utils.ProcessList(), nil
}

// Stop stop the designed Process
func (svc *ProcessManagerHandler) Stop(ctx context.Context, uuid string) {
	utils.ProcessCancelUUID(uuid)
}
