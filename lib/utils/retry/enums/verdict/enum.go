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

//go:generate stringer -type=Enum

package verdict

// Enum tells the choice made by an Arbiter, to retry or not
type Enum int

const (
	// Done tells the arbiter decided the last retry succeeded
	Done Enum = iota
	// Retry tells the arbiter decided to execute the next retry
	Retry
	// Abort tells the arbiter decided something wrong occurred; the Action must stop with error
	Abort
)
