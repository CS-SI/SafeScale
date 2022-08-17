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

package converters

// Contains functions that are used to convert from everything else

import (
	"fmt"
	"strconv"
	"strings"
	"text/scanner"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// BucketListToProtocol convert a list of string into a *protocol.BucketListResponse
func BucketListToProtocol(in []string) *protocol.BucketListResponse {
	var buckets []*protocol.BucketResponse
	for _, name := range in {
		buckets = append(buckets, &protocol.BucketResponse{Name: name})
	}
	return &protocol.BucketListResponse{
		Buckets: buckets,
	}
}

// HostSizingRequirementsFromStringToAbstract HostSizingFromStringToAbstract converts host sizing requirements from string to *abstract.HostSizingRequirements
func HostSizingRequirementsFromStringToAbstract(in string) (*abstract.HostSizingRequirements, int, fail.Error) {
	tokens, rerr := parseSizingString(in)
	if rerr != nil {
		return nil, 0, rerr
	}

	var err error
	out := abstract.HostSizingRequirements{}
	if t, ok := tokens["cpu"]; ok {
		min, max, xerr := t.Validate()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, 0, xerr
		}

		if min != "" {
			out.MinCores, err = strconv.Atoi(min)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, 0, fail.SyntaxError("invalid min value '%s' for 'cpu'", min)
			}
		}
		if max != "" {
			out.MaxCores, err = strconv.Atoi(max)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, 0, fail.SyntaxError("invalid max value '%s' for 'cpu'", max)
			}
		}
	}
	var count int
	if t, ok := tokens["count"]; ok {
		c, _, xerr := t.Validate()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, 0, xerr
		}

		count, err = strconv.Atoi(c)
		err = debug.InjectPlannedError(err)
		if err != nil {
			return nil, 0, fail.SyntaxError("invalid value '%s' for 'count'", c)
		}
	}
	if t, ok := tokens["cpufreq"]; ok {
		min, _, xerr := t.Validate()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, 0, xerr
		}

		if min != "" {
			c, err := strconv.ParseFloat(min, 64)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, 0, fail.SyntaxError("invalid value '%s' for 'cpufreq'", min)
			}

			out.MinCPUFreq = float32(c)
		}
	}
	if t, ok := tokens["gpu"]; ok {
		min, _, xerr := t.Validate()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, 0, xerr
		}

		if min != "" {
			out.MinGPU, err = strconv.Atoi(min)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, 0, fail.SyntaxError("invalid value '%s' for 'gpu'", min)
			}
		}
	} else {
		out.MinGPU = -1
	}
	if t, ok := tokens["ram"]; ok {
		min, max, xerr := t.Validate()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, 0, xerr
		}

		if min != "" {
			c, err := strconv.ParseFloat(min, 64)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, 0, fail.SyntaxError("invalid min value '%s' for 'ram'", min)
			}

			out.MinRAMSize = float32(c)
		}
		if max != "" {
			c, err := strconv.ParseFloat(max, 64)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, 0, fail.SyntaxError("invalid max value '%s' for 'ram'", max)
			}

			out.MaxRAMSize = float32(c)
		}
	}
	if t, ok := tokens["disk"]; ok {
		min, max, xerr := t.Validate()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, 0, xerr
		}

		if min != "" {
			out.MinDiskSize, err = strconv.Atoi(min)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, 0, fail.SyntaxError("invalid min value '%s' for 'disk'", min)
			}
		}

		if max != "" {
			out.MaxDiskSize, err = strconv.Atoi(max)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return nil, 0, fail.SyntaxError("invalid max value '%s' for 'disk'", max)
			}
		}
	}
	if t, ok := tokens["template"]; ok {
		var xerr fail.Error
		out.Template, _, xerr = t.Validate()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, 0, xerr
		}
	}
	return &out, count, nil
}

// NodeCountFromStringToInteger extracts initial node count from string
func NodeCountFromStringToInteger(in string) (int, fail.Error) {
	if in == "" {
		return 0, nil
	}

	tokens, xerr := parseSizingString(in)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	if t, ok := tokens["count"]; ok {
		if min, _, xerr := t.Validate(); xerr == nil && min != "" {
			count, err := strconv.Atoi(min)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return 0, fail.SyntaxError("invalid value '%s' for 'count'", min)
			}

			return count, nil
		}
	}

	return 0, nil
}

// sizingToken describes a token (<keyword> <operator> <value>)
type sizingToken struct {
	members []string

	pos uint8
}

// newSizingToken creates a new token
func newSizingToken() *sizingToken {
	t := sizingToken{}
	t.members = make([]string, 3)
	return &t
}

// Push sets an item of the token based on its current content
func (t *sizingToken) Push(item string) fail.Error {
	if t == nil {
		return fail.InconsistentError("sizingToken is nil")
	}
	if t.IsFull() {
		return fail.NotAvailableError("token is full")
	}

	item = strings.ToLower(item)
	t.members[t.pos] = item
	t.pos++
	return nil
}

// IsFull tells if the token is full
func (t *sizingToken) IsFull() bool {
	return t != nil && t.pos >= 3
}

// GetKeyword returns the keyword member of the token (pos == 0)
func (t *sizingToken) GetKeyword() (string, fail.Error) {
	if t.pos > 0 {
		return t.members[0], nil
	}
	return "", fail.InvalidRequestError("keyword is not set in token")
}

// GetOperator returns the operator member of the token (pos == 1)
func (t *sizingToken) GetOperator() (string, fail.Error) {
	if t != nil && t.pos > 1 {
		return t.members[1], nil
	}
	return "", fail.InvalidRequestError("operator is not set in token")
}

// GetValue returns the value member of the token (pos == 2)
func (t *sizingToken) GetValue() (string, fail.Error) {
	if t.pos > 2 {
		return t.members[2], nil
	}
	return "", fail.InvalidRequestError("value is not set in token")
}

// String returns a string representing the token
func (t *sizingToken) String() string {
	if t == nil {
		return ""
	}
	return strings.Join(t.members, " ")
}

// Validate validates value in relation with operator, and returns min and max values if validated
func (t *sizingToken) Validate() (string, string, fail.Error) {
	if !t.IsFull() {
		return "", "", fail.InvalidRequestError("token is not complete")
	}

	keyword := t.members[0]
	operator := t.members[1]
	value := t.members[2]
	switch operator {
	case "~": // "~" means "[<value>-<value*2>]"
		if keyword == "count" {
			return "", "", fail.InvalidRequestError("'count' can only use '='")
		}
		if keyword == "template" {
			return "", "", fail.InvalidRequestError("'template' can only use '='")
		}

		vali, err := strconv.Atoi(value)
		err = debug.InjectPlannedError(err)
		if err != nil {
			valf, err := strconv.ParseFloat(value, 64)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return "", "", fail.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
			return fmt.Sprintf("%.01f", valf), fmt.Sprintf("%.01f", 2*valf), nil
		}
		return fmt.Sprintf("%d", vali), fmt.Sprintf("%d", 2*vali), nil
	case "=":
		if keyword == "template" {
			return value, "", nil
		}
		if keyword != "count" {
			if value[0] == '[' && value[len(value)-1] == ']' {
				value = value[1 : len(value)-1]
				splitted := strings.Split(value, "-")
				if len(splitted) != 2 {
					return "", "", fail.InvalidRequestError("value '%s' of '%s' token isn't a valid interval", value, keyword)
				}
				min := splitted[0]
				_, err := strconv.ParseFloat(min, 64)
				err = debug.InjectPlannedError(err)
				if err != nil {
					return "", "", fail.InvalidRequestError("first value '%s' of interval for token '%s' isn't a valid number: %s", min, keyword, err.Error())
				}
				max := splitted[1]
				_, err = strconv.ParseFloat(max, 64)
				err = debug.InjectPlannedError(err)
				if err != nil {
					return "", "", fail.InvalidRequestError("second value '%s' of interval for token '%s' isn't a valid number: %s", max, keyword, err.Error())
				}
				return min, max, nil
			}
		}
		_, err := strconv.Atoi(value)
		err = debug.InjectPlannedError(err)
		if err != nil {
			if keyword != "count" {
				_, err = strconv.ParseFloat(value, 64)
			}
			err = debug.InjectPlannedError(err)
			if err != nil {
				return "", "", fail.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
		}
		return value, value, nil

	case "lt":
		fallthrough
	case "<":
		if keyword == "count" {
			return "", "", fail.InvalidRequestError("'count' can only use '='")
		}
		if keyword == "template" {
			return "", "", fail.InvalidRequestError("'template' can only use '='")
		}

		vali, err := strconv.Atoi(value)
		err = debug.InjectPlannedError(err)
		if err != nil {
			valf, err := strconv.ParseFloat(value, 64)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return "", "", fail.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
			return "", fmt.Sprintf("%.01f", valf-0.1), nil
		}
		return "", fmt.Sprintf("%d", vali-1), nil

	case "le":
		fallthrough
	case "<=":
		if keyword == "count" {
			return "", "", fail.InvalidRequestError("'count' can only use '='")
		}
		if keyword == "template" {
			return "", "", fail.InvalidRequestError("'template' can only use '='")
		}

		_, err := strconv.Atoi(value)
		err = debug.InjectPlannedError(err)
		if err != nil {
			_, err := strconv.ParseFloat(value, 64)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return "", "", fail.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
		}
		return "", value, nil

	case "gt":
		fallthrough
	case ">":
		if keyword == "count" {
			return "", "", fail.InvalidRequestError("'count' can only use '='")
		}
		if keyword == "template" {
			return "", "", fail.InvalidRequestError("'template' can only use '='")
		}

		vali, err := strconv.Atoi(value)
		err = debug.InjectPlannedError(err)
		if err != nil {
			valf, err := strconv.ParseFloat(value, 64)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return "", "", fail.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
			return fmt.Sprintf("%.01f", valf+0.1), "", nil
		}
		return fmt.Sprintf("%d", vali+1), "", nil

	case "ge":
		fallthrough
	case ">=":
		if keyword == "count" {
			return "", "", fail.InvalidRequestError("'count' can only use '='")
		}

		_, err := strconv.Atoi(value)
		err = debug.InjectPlannedError(err)
		if err != nil {
			_, err := strconv.ParseFloat(value, 64)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return "", "", fail.InvalidRequestError(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
		}
		return value, "", nil
	}

	return "", "", fail.InvalidRequestError(fmt.Sprintf("operator '%s' of token '%s' is not supported", operator, keyword))
}

func merge(ms ...map[string]*sizingToken) map[string]*sizingToken {
	res := map[string]*sizingToken{}

	for _, m := range ms {
		for k, v := range m {
			res[k] = v
		}
	}
	return res
}

func parseSizingString(request string) (map[string]*sizingToken, fail.Error) {
	var parsed []map[string]*sizingToken

	if strings.Contains(request, ",") {
		fragments := strings.Split(request, ",")
		for _, frag := range fragments {
			apa, err := newParseSizingString(frag)
			if err != nil {
				return nil, err
			}
			parsed = append(parsed, apa)
		}
	} else {
		apa, err := newParseSizingString(request)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, apa)
	}
	return merge(parsed...), nil
}

// parseSizingString transforms a string to a list of tokens
func newParseSizingString(request string) (map[string]*sizingToken, fail.Error) {
	var (
		s       scanner.Scanner
		tokens  = map[string]*sizingToken{}
		mytoken *sizingToken
	)

	if request == "" {
		return nil, fail.NewError("empty string")
	}

	// this handles the specific case "template=whatever", the code a few lines below expect numeric comparisons and does not behave the same way
	cleaned := strings.TrimSpace(request)
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	if strings.HasPrefix(cleaned, "template=") {
		if strings.Contains(cleaned, "=") {
			frag := strings.Split(cleaned, "=")
			if len(frag) == 2 {
				tokens["template"] = &sizingToken{
					members: []string{"template", "=", frag[1]},
					pos:     3,
				}
				return tokens, nil
			}
		}
		return nil, fail.SyntaxError("unexpected format: '%s', only 'template=YourTemplateNameHere' is allowed", request)
	}

	s.Init(strings.NewReader(request))
	// s.Mode = scanner.ScanInts | scanner.ScanFloats | scanner.ScanChars | scanner.ScanRawStrings

	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		t := s.TokenText()

		switch t {
		case ",":
			if mytoken == nil {
				continue
			}
			p := s.Pos()
			return nil, fail.SyntaxError("misplace separator ',' at line %d, column %d", p.Line, p.Column)

		case "[": // Manages value in the form [a-b]
			for tok = s.Scan(); tok != scanner.EOF; tok = s.Scan() {
				if s.TokenText() == "]" {
					t += "]"
					break
				}
				t += s.TokenText()
			}

		case "-": // Manages negative number (can be used for gpu)
			if tok = s.Scan(); tok == scanner.EOF {
				p := s.Pos()
				return nil, fail.SyntaxError("invalid content '%s' at line %d, column %d", request, p.Line, p.Column)
			}
			t += s.TokenText()
		}

		if mytoken == nil {
			mytoken = newSizingToken()
		}
		err := mytoken.Push(t)
		err = debug.InjectPlannedFail(err)
		if err != nil {
			p := s.Pos()
			return nil, fail.SyntaxError("invalid content '%s' at line %d, column %d", request, p.Line, p.Column)
		}

		// handles the cases >= or <=
		if val, xerr := mytoken.GetOperator(); xerr == nil && (val == ">" || val == "<") {
			if tok = s.Scan(); tok != scanner.EOF {
				if s.TokenText() == "=" {
					mytoken.members[mytoken.pos-1] += "="
				} else {
					xerr = mytoken.Push(s.TokenText())
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						p := s.Pos()
						return nil, fail.NewError("invalid content '%s' at line %d, column %d", request, p.Line, p.Column)
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
