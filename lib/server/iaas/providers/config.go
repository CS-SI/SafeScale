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

package providers

//go:generate mockgen -destination=../mocks/mock_config.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas/providers Config

// Config represents key/value configuration.
type Config interface {
	// Config gets a string configuration value and a
	// bool indicating whether the value was present or not.
	Config(name string) (interface{}, bool)
	//Get is an alias to Config()
	Get(name string) (interface{}, bool)
	//Set sets the configuration name to specified value
	Set(name string, value interface{})
	//GetString returns a string corresponding to the key, empty string if it doesn't exist
	GetString(name string) string
	//GetSliceOfStrings returns a slice of strings corresponding to the key, empty string slice if it doesn't exist
	GetSliceOfStrings(name string) []string
	//GetMapOfStrings returns a string map of strings corresponding to the key, empty map if it doesn't exist
	GetMapOfStrings(name string) map[string]string
	//GetInteger returns an integer corresponding to the key, 0 if it doesn't exist
	GetInteger(name string) int
}

// ConfigMap is a map[string]string that implements
// the Config method.
type ConfigMap map[string]interface{}

// Config gets a string configuration value and a
// bool indicating whether the value was present or not.
func (c ConfigMap) Config(name string) (interface{}, bool) {
	val, ok := c[name]
	return val, ok
}

// Get is an alias to Config()
func (c ConfigMap) Get(name string) (interface{}, bool) {
	return c.Config(name)
}

// GetString returns a string corresponding to the key, empty string if it doesn't exist
func (c ConfigMap) GetString(name string) string {
	val, ok := c.Get(name)
	if ok {
		return val.(string)
	}
	return ""
}

// GetSliceOfStrings returns a string slice corresponding to the key, empty string slice if it doesn't exist
func (c ConfigMap) GetSliceOfStrings(name string) []string {
	val, ok := c.Get(name)
	if ok {
		return val.([]string)
	}
	return []string{}
}

// GetMapOfStrings returns a string map of strings corresponding to the key, empty map if it doesn't exist
func (c ConfigMap) GetMapOfStrings(name string) map[string]string {
	val, ok := c.Get(name)
	if ok {
		return val.(map[string]string)
	}
	return map[string]string{}
}

// GetInteger returns an integer corresponding to the key, 0 if it doesn't exist
func (c ConfigMap) GetInteger(name string) int {
	val, ok := c.Get(name)
	if ok {
		return val.(int)
	}
	return 0
}

// Set sets name configuration to value
func (c ConfigMap) Set(name string, value interface{}) {
	c[name] = value
}
