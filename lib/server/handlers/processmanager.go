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

package handlers

import (
	"context"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/utils"
)

//go:generate mockgen -destination=../mocks/mock_processmanager.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers ProcessManagerAPI

// ProcessManagerAPI defines API to manipulate process
type ProcessManagerAPI interface {
	List(ctx context.Context) (map[string]string, error)
	Stop(ctx context.Context, uuid string)
}

// ProcessManagerHandler service
type ProcessManagerHandler struct {
	service iaas.Service
}

// NewProcessManagerHandler creates a Volume service
func NewProcessManagerHandler(svc iaas.Service) ProcessManagerAPI {
	return &ProcessManagerHandler{
		service: svc,
	}
}

// List returns the Running Process list
func (pmh *ProcessManagerHandler) List(ctx context.Context) (map[string]string, error) {
	return utils.ProcessList(), nil
}

// Stop stop the designed Process
func (pmh *ProcessManagerHandler) Stop(ctx context.Context, uuid string) {
	utils.ProcessCancelUUID(uuid)
}
