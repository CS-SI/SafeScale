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
	"fmt"

	"github.com/CS-SI/SafeScale/iaas"
)

//go:generate mockgen -destination=../mocks/mock_dataapi.go -package=mocks github.com/CS-SI/SafeScale/safescale/server/handlers DataAPI

// DataAPI defines API to manipulate Data
type DataAPI interface {
	Push(ctx context.Context, fileLocalPath string, fileName string) error
	Get(ctx context.Context, fileLocalPath string, fileName string) error
}

// DataHandler bucket service
type DataHandler struct {
	storageServices *iaas.StorageServices
}

// NewDataHandler creates a Data service
func NewDataHandler(svc *iaas.StorageServices) DataAPI {
	return &DataHandler{storageServices: svc}
}

//Push ...
func (handler *DataHandler) Push(ctx context.Context, fileLocalPath string, fileName string) error {
	fmt.Println("Push handler Not implemented yet")
	fmt.Printf("%s !-! %s\n", fileLocalPath, fileName)
	return nil
}

//Get ...
func (handler *DataHandler) Get(ctx context.Context, fileLocalPath string, fileName string) error {
	fmt.Println("Get handler Not implemented yet")
	fmt.Printf("%s !-! %s\n", fileLocalPath, fileName)
	return nil
}
