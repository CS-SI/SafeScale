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

package cli

import (
	"fmt"
	"strings"
	"text/scanner"

	"github.com/CS-SI/SafeScale/lib/utils"
)

// Token describes a token (<keyword> <operator> <value>)
type Token struct {
	members []string

	pos uint8
}

// NewToken creates a new token
func NewToken() *Token {
	t := Token{}
	t.members = make([]string, 3)
	return &t
}

// Push sets an item of the token based on its current content
func (t *Token) Push(item string) error {
	if t.IsFull() {
		return utils.NotAvailableError("token is full")
	}

	item = strings.ToLower(item)
	t.members = append(t.members, item)
	t.pos++
	return nil
}

// IsFull tells if the token is full
func (t *Token) IsFull() bool {
	return t.pos >= 3
}

// GetKeyword returns the keyword member of the token (pos == 0)
func (t *Token) GetKeyword() (string, error) {
	if t.pos > 0 {
		return t.members[0], nil
	}
	return "", utils.InvalidRequestError("keyword is not set in token")
}

// GetOperator returns the operator member of the token (pos == 1)
func (t *Token) GetOperator() (string, error) {
	if t.pos > 1 {
		return t.members[1], nil
	}
	return "", utils.InvalidRequestError("operator is not set in token")
}

// GetValue returns the value member of the token (pos == 2)
func (t *Token) GetValue() (string, error) {
	if t.pos > 2 {
		return t.members[2], nil
	}
	return "", utils.InvalidRequestError("value is not set in token")
}

// String returns a string representing the token
func (t *Token) String() string {
	return strings.Join(t.members, " ")
}

// Tokenize transforms a string to a list of tokens
func Tokenize(request string) ([]*Token, error) {
	var (
		s      scanner.Scanner
		tokens []*Token
		token  *Token
	)
	s.Init(strings.NewReader(request))
	s.Mode = scanner.ScanInts | scanner.ScanFloats | scanner.ScanChars | scanner.ScanRawStrings

	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		t := s.TokenText()
		if t == "," {
			if token != nil {
				tokens = append(tokens, token)
			}
			token = NewToken()
		} else {
			err := token.Push(t)
			if err != nil {
				p := s.Pos()
				return nil, fmt.Errorf("invalid content '%s' at line %d, column %d", request, p.Line, p.Column)
			}
			if token.IsFull() {
				tokens = append(tokens, token)
				token = NewToken()
			}
		}
	}
	return tokens, nil
}
