/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package cache

import (
	"fmt"

	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// reservation is a struct to simulate a content of a Entry to "reserve" a key
type reservation struct {
	key       string
	observers map[string]observer.Observer
}

func (rc reservation) GetID() string {
	return rc.key
}

func (rc reservation) GetName() string {
	return rc.key
}

func (rc reservation) AddObserver(o observer.Observer) error {
	if _, ok := rc.observers[o.GetID()]; ok {
		return fail.DuplicateError("there is already an Observer identified by '%s'", o.GetID())
	}

	rc.observers[o.GetID()] = o

	return nil
}

func (rc reservation) NotifyObservers() error {
	for _, ob := range rc.observers {
		ob.SignalChange(rc.key)
	}
	return nil
}

func (rc reservation) RemoveObserver(name string) error {
	if _, ok := rc.observers[name]; !ok {
		return fmt.Errorf("not there")
	}
	delete(rc.observers, name)
	return nil
}

func (rc reservation) Released() {
	for _, ob := range rc.observers {
		ob.MarkAsFreed(rc.key)
	}
}

func (rc reservation) Destroyed() {
	for _, ob := range rc.observers {
		ob.MarkAsFreed(rc.key)
	}
}
