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
	"fmt"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"

	"github.com/sethvargo/go-password/password"
)

var generator *password.Generator

// GeneratePassword generates a password with length at least 12
func GeneratePassword(length uint8) (string, error) {
	if length < 12 {
		return "", scerr.InvalidParameterError("length", "cannot be under 12")
	}
	numsym := int(length) / 3
	pass, err := generator.Generate(int(length), numsym, numsym, false, true)
	if err != nil {
		return "", err
	}
	return pass, nil
}

func init() {
	var err error
	// generator is created with characters allowed
	// Removed characters:
	// - confusing characters like: il|! or 0O
	// - alphabetic characters that can moved between QWERTY and AZERTY: AaQqWwZz
	// - symbols that can be difficult to find on different layouts, like: #_[]{}
	generator, err = password.NewGenerator(&password.GeneratorInput{
		LowerLetters: "bcdefghjknprstuvxy",
		UpperLetters: "BCDEFGHJKLNPRSTUVXY",
		Digits:       "123456789",
		Symbols:      "-+*/.,:;()_",
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create password generator: %v!", err))
	}
}
