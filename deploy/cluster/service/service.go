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

package service

import (
	"fmt"

	svcapi "github.com/CS-SI/SafeScale/deploy/service/api"

	installapi "github.com/CS-SI/SafeScale/deploy/install/api"
)

// EnlistAsService joins to a component a manager to make the component serviceable
func EnlistAsService(c installapi.ComponentAPI) (svcapi.ServiceAPI, error) {
	// Searching in managerList if it exists a manager named as the component
	var m svcapi.Manager
	var ok bool
	if m, ok = managerList[c.GetName()]; !ok {
		return nil, fmt.Errorf("failed to find how to manage component '%s'", c.GetName())
	}

	// Check everything is in place...
	if m.StartScript == "" {
		panic("Invalid empty value in m.StartScript!")
	}
	if m.StopScript == "" {
		panic("Invalid empty value in m.StopScript!")
	}
	if m.StateScript == "" {
		panic("Invalid empty value in m.StateScript!")
	}

	return &Service{
		component: c,
		manager:   &m,
	}, nil
}

// GetName returns the name of the component
func (s *Service) GetName() string {
	return s.component.GetName()
}

// GetComponent returns the component enlisted as a service
func (s *Service) GetComponent() installapi.ComponentAPI {
	return s.component
}

// State ...
func (s *Service) State(target installapi.Target) error {
	return brokerclient.New().Ssh.Run(target.GetName(), s.manager.StateScript, brokerclient.DefaultTimeout)
}

// Start ...
func (s *Service) Start(target installapi.Target) error {
	return brokerclient.New().Ssh.Run(target.GetName(), s.manager.StartScript, brokerclient.DefaultTimeout)
}

// Stop ...
func (s *Service) Stop(target installapi.Target) error {
	return brokerclient.New().Ssh.Run(target.GetName(), s.manager.StopScript, brokerclient.DefaultTimeout)
}

// Restart ...
func (s *Service) Restart(target installapi.Target) error {
	err := s.Stop(target)
	if err != nil {
		return err
	}
	return s.Start(target)
}

// Pause ...
func (s *Service) Pause(target installapi.Target) error {
	return brokerclient.New().Ssh.Run(target.GetName(), s.manager.PauseScript, brokerclient.DefaultTimeout)
}

// Resume ...
func (s *Service) Resume(target installapi.Target) error {
	return brokerclient.New().Ssh.Run(target.GetName(), s.manager.ResumeScript, brokerclient.DefaultTimeout)
}
