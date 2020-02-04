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

package cli

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"strconv"
	"strings"
	"text/scanner"
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
		return scerr.NotAvailableError("token is full")
	}

	item = strings.ToLower(item)
	t.members[t.pos] = item
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
	return "", scerr.InvalidRequestError("keyword is not set in token")
}

// GetOperator returns the operator member of the token (pos == 1)
func (t *Token) GetOperator() (string, error) {
	if t.pos > 1 {
		return t.members[1], nil
	}
	return "", scerr.InvalidRequestError("operator is not set in token")
}

// GetValue returns the value member of the token (pos == 2)
func (t *Token) GetValue() (string, error) {
	if t.pos > 2 {
		return t.members[2], nil
	}
	return "", scerr.InvalidRequestError("value is not set in token")
}

// String returns a string representing the token
func (t *Token) String() string {
	return strings.Join(t.members, " ")
}

// Validate validates value in relation with operator, and returns min and max values if validated
func (t *Token) Validate() (string, string, error) {
	if !t.IsFull() {
		return "", "", scerr.InvalidRequestError("token isn't complete")
	}

	keyword := t.members[0]
	operator := t.members[1]
	value := t.members[2]
	switch operator {
	case "~":
		// "~" means "[<value>-<value*2>]"
		vali, err := strconv.Atoi(value)
		if err != nil {
			valf, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", scerr.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
			return fmt.Sprintf("%.01f", valf), fmt.Sprintf("%.01f", 2*valf), nil
		}
		return fmt.Sprintf("%d", vali), fmt.Sprintf("%d", 2*vali), nil
	case "=":
		if value[0] == '[' && value[len(value)-1] == ']' {
			value = value[1 : len(value)-1]
			splitted := strings.Split(value, "-")
			if len(splitted) != 2 {
				return "", "", scerr.InvalidRequestError(fmt.Sprintf("value '%s' of '%s' token isn't a valid interval", value, keyword))
			}
			min := splitted[0]
			_, err := strconv.ParseFloat(min, 64)
			if err != nil {
				return "", "", scerr.InvalidRequestError(fmt.Sprintf("first value '%s' of interval for token '%s' isn't a valid number: %s", min, keyword, err.Error()))
			}
			max := splitted[1]
			_, err = strconv.ParseFloat(max, 64)
			if err != nil {
				return "", "", scerr.InvalidRequestError(fmt.Sprintf("second value '%s' of interval for token '%s' isn't a valid number: %s", max, keyword, err.Error()))
			}
			return min, max, nil
		}
		_, err := strconv.Atoi(value)
		if err != nil {
			_, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", scerr.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
		}
		return value, value, nil

	case "lt":
		fallthrough
	case "<":
		vali, err := strconv.Atoi(value)
		if err != nil {
			valf, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", scerr.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
			return "", fmt.Sprintf("%.01f", valf-0.1), nil
		}
		return "", fmt.Sprintf("%d", vali-1), nil

	case "le":
		fallthrough
	case "<=":
		_, err := strconv.Atoi(value)
		if err != nil {
			_, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", scerr.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
		}
		return "", value, nil

	case "gt":
		fallthrough
	case ">":
		vali, err := strconv.Atoi(value)
		if err != nil {
			valf, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", scerr.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
			return fmt.Sprintf("%.01f", valf+0.1), "", nil
		}
		return fmt.Sprintf("%d", vali+1), "", nil

	case "ge":
		fallthrough
	case ">=":
		_, err := strconv.Atoi(value)
		if err != nil {
			_, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", scerr.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
		}
		return value, "", nil
	}

	return "", "", scerr.InvalidRequestError(fmt.Sprintf("operator '%s' of token '%s' is not supported", operator, keyword))
}

// ParseParameter transforms a string to a list of tokens
func ParseParameter(request string) (map[string]*Token, error) {
	var (
		s       scanner.Scanner
		tokens  = map[string]*Token{}
		mytoken *Token
	)
	s.Init(strings.NewReader(request))
	// s.Mode = scanner.ScanInts | scanner.ScanFloats | scanner.ScanChars | scanner.ScanRawStrings

	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		t := s.TokenText()
		if t == "," {
			if mytoken == nil {
				continue
			}
			p := s.Pos()
			return nil, fmt.Errorf("misplace separator ',' at line %d, column %d", p.Line, p.Column)
		}

		if mytoken == nil {
			mytoken = NewToken()
		}

		// Manages value in the form [a-b]
		if t == "[" {
			for tok = s.Scan(); tok != scanner.EOF; tok = s.Scan() {
				if s.TokenText() == "]" {
					t += "]"
					break
				}
				t += s.TokenText()
			}
		}

		err := mytoken.Push(t)
		if err != nil {
			p := s.Pos()
			return nil, fmt.Errorf("invalid content '%s' at line %d, column %d", request, p.Line, p.Column)
		}

		// handles the cases >= or <=
		if val, err := mytoken.GetOperator(); err == nil && (val == ">" || val == "<") {
			if tok = s.Scan(); tok != scanner.EOF {
				if s.TokenText() == "=" {
					mytoken.members[mytoken.pos-1] += "="
				} else {
					err = mytoken.Push(s.TokenText())
					if err != nil {
						p := s.Pos()
						return nil, fmt.Errorf("invalid content '%s' at line %d, column %d", request, p.Line, p.Column)
					}
				}
			}
		}
		if mytoken.IsFull() {
			name, _ := mytoken.GetKeyword()
			tokens[name] = mytoken
			mytoken = nil
		}
	}
	return tokens, nil
}
