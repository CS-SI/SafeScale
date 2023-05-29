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

package handlers

import (
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	labelfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/label"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// LabelHandler defines API to manipulate tags
type LabelHandler interface {
	Delete(ref string) fail.Error
	List(listTag bool) ([]resources.Label, fail.Error)
	Inspect(ref string) (resources.Label, fail.Error)
	Create(name string, hasDefault bool, defaultValue string) (resources.Label, fail.Error)
}

// labelHandler Label service
type labelHandler struct {
	job backend.Job
}

// NewTagHandler creates a Label service
func NewTagHandler(job backend.Job) LabelHandler {
	return &labelHandler{job: job}
}

// List returns the network list
func (handler *labelHandler) List(listTag bool) (list []resources.Label, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	browseInstance, xerr := labelfactory.New(handler.job.Service(), isTerraform)
	if xerr != nil {
		return nil, xerr
	}

	if !isTerraform {
		xerr = browseInstance.Browse(handler.job.Context(), func(label *abstract.Label) fail.Error {
			labelInstance, innerXErr := labelfactory.Load(handler.job.Context(), handler.job.Service(), label.ID, isTerraform)
			if innerXErr != nil {
				return innerXErr
			}

			isTag, innerXErr := labelInstance.IsTag(handler.job.Context())
			if innerXErr != nil {
				return innerXErr
			}

			if listTag == isTag {
				list = append(list, labelInstance)
			}

			return nil
		})
		if xerr != nil {
			return nil, xerr
		}
		return list, nil
	}

	return labelfactory.LoadAll(handler.job.Context(), handler.job.Service(), isTerraform)
}

// Delete deletes Label referenced by ref
func (handler *labelHandler) Delete(ref string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	instance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), ref, isTerraform)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return abstract.ResourceNotFoundError("tag", ref)
		default:
			logrus.WithContext(handler.job.Context()).Debugf("failed to delete tag: %+v", xerr)
			return xerr
		}
	}

	return instance.Delete(handler.job.Context())
}

// Inspect returns the tag identified by ref and its attachment (if any)
func (handler *labelHandler) Inspect(ref string) (_ resources.Label, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty!")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	instance, xerr := labelfactory.Load(handler.job.Context(), handler.job.Service(), ref, isTerraform)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, abstract.ResourceNotFoundError("tag", ref)
		default:
			return nil, xerr
		}
	}

	return instance, nil
}

// Create a tag
func (handler *labelHandler) Create(name string, hasDefault bool, defaultValue string) (instance resources.Label, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty!")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	instance, xerr = labelfactory.New(handler.job.Service(), isTerraform)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = instance.Create(handler.job.Context(), name, hasDefault, defaultValue); xerr != nil {
		return nil, xerr
	}
	return instance, nil
}
