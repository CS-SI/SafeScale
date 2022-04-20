/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package data

//go:generate minimock -o mocks/mock_annotatable.go -i github.com/CS-SI/SafeScale/v21/lib/utils/data.Annotatable

// Annotation ...
type Annotation interface{}

// Annotations ...
type Annotations Map

// Annotatable ...
type Annotatable interface {
	Annotate(key string, value Annotation) Annotatable // adds an annotation to instance, returning instance
	Annotations() Annotations                          // gives the annotations
	Annotation(key string) (Annotation, bool)          // gives one annotation identified by field
}
