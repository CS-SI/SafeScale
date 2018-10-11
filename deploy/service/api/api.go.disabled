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

package api

import (
	installapi "github.com/CS-SI/SafeScale/deploy/install/api"
)

// TODO Finish Mock
// //go:generate mockgen -destination=../mocks/mock_serviceapi.go -package=mocks github.com/CS-SI/SafeScale/deploy/service/api ServiceAPI

// ServiceAPI defines the API of an installable service, which is a component with state
type ServiceAPI interface {
	// GetName ...
	GetName() string
	// GetComponent ...
	GetComponent() installapi.ComponentAPI
	// State ...
	State(installapi.Target) error
	// Start ...
	Start(installapi.Target) error
	// Stop ...
	Stop(installapi.Target) error
}

// Manager defines the data needed for the service object to manage a component that have to react as a service
// (basically, some scripts to give order to the component)
type Manager struct {
	StartScript string
	StopScript  string
	StateScript string
}
