/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
)

type jobInfo struct {
	commandName string
	launchTime  time.Time
	context     context.Context
	cancelFunc  func()
}

func (ji *jobInfo) toString() string {
	return fmt.Sprintf("Task : %s\nCreation time : %s", ji.commandName, ji.launchTime.String())
}

var (
	jobMap          = map[string]jobInfo{}
	mutexJobManager sync.Mutex
)

// JobRegister ...
func JobRegister(ctx context.Context, cancelFunc func(), command string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("no uuid in grpc metadata")
	}
	mutexJobManager.Lock()
	defer mutexJobManager.Unlock()

	jobMap[md.Get("uuid")[0]] = jobInfo{
		commandName: command,
		launchTime:  time.Now(),
		context:     ctx,
		cancelFunc:  cancelFunc,
	}

	return nil
}

// JobCancelUUID ...
func JobCancelUUID(uuid string) {
	mutexJobManager.Lock()
	defer mutexJobManager.Unlock()
	if info, found := jobMap[uuid]; found {
		info.cancelFunc()
	}
}

// JobDeregisterUUID ...
func JobDeregisterUUID(uuid string) {
	mutexJobManager.Lock()
	defer mutexJobManager.Unlock()

	delete(jobMap, uuid)
}

// JobDeregister ...
func JobDeregister(ctx context.Context) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logrus.Errorf("Trying to deregister a job without uuid!")
	} else {
		JobDeregisterUUID(md.Get("uuid")[0])
	}
}

// JobList ...
func JobList() map[string]string {
	listMap := map[string]string{}
	for uuid, info := range jobMap {
		listMap[uuid] = info.toString()
	}
	return listMap
}
