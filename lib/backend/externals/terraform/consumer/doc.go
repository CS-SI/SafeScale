/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

// Package consumer package consumer proposes a way to invoke terraform command-line for use in provider drivers
//
// A typical workflow is:
//
//	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
//	if xerr != nil {
//	    return xerr
//	}
//	defer func() { _ = renderer.Close() }()
//
//	def, xerr := renderer.Assemble(inctx, ahf)
//	if xerr != nil {
//	    return xerr
//	}
//
//	outputs, innerXErr = renderer.Apply(inctx, def)
package consumer
