//go:build !release
// +build !release

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

package debug

import (
	"context"

	"github.com/sirupsen/logrus"
)

// IgnoreError logs an error that's considered not important by the caller
func IgnoreError(err error) {
	if err != nil { // nolint
		logrus.Debugf("ignoring error [%s]", err)
		// logrus.Debugf("ignoring error stack: %s", string(debug.Stack()))
	}
}

func IgnoreError2(ctx context.Context, err error) {
	if err != nil { // nolint
		logrus.WithContext(ctx).Debugf("ignoring error [%s]", err)
		// logrus.WithContext(ctx).Debugf("ignoring error stack: %s", string(debug.Stack()))
	}
}
