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

package utils

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"
)

type processInfo struct {
	commandName string
	launchTime  time.Time
	context     context.Context
	cancelFunc  func()
}

func (pi *processInfo) toString() string {
	return fmt.Sprintf("Task : %s\nCreation time : %s", pi.commandName, pi.launchTime.String())
}

var processMap map[string]processInfo
var mutexProcessManager sync.Mutex

// ProcessRegister ...
func ProcessRegister(ctx context.Context, cancelFunc func(), command string) error {
	if processMap == nil {
		processMap = map[string]processInfo{}
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("No uuid in grpc metadata")
	}
	mutexProcessManager.Lock()
	processMap[md.Get("uuid")[0]] = processInfo{
		commandName: command,
		launchTime:  time.Now(),
		context:     ctx,
		cancelFunc:  cancelFunc,
	}
	mutexProcessManager.Unlock()
	return nil
}

// ProcessCancelUUID ...
func ProcessCancelUUID(uuid string) {
	mutexProcessManager.Lock()
	defer mutexProcessManager.Unlock()
	if info, found := processMap[uuid]; found {
		info.cancelFunc()
	}
}

// ProcessDeregisterUUID ...
func ProcessDeregisterUUID(uuid string) {
	mutexProcessManager.Lock()
	defer mutexProcessManager.Unlock()
	delete(processMap, uuid)
}

// ProcessDeregister ...
func ProcessDeregister(ctx context.Context) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		panic("no uuid in metadata")
	}
	ProcessDeregisterUUID(md.Get("uuid")[0])
}

// ProcessList ...
func ProcessList() map[string]string {
	listMap := map[string]string{}
	for uuid, info := range processMap {
		listMap[uuid] = info.toString()
	}
	return listMap
}
