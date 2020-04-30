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

package converters

// Contains functions that are used to convert from everything else

import (
	"fmt"
	"strconv"
	"strings"
	"text/scanner"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/sirupsen/logrus"
)

// BucketListToProtocol convert a list of string into a *ContainerLsit
func BucketListToProtocol(in []string) *protocol.BucketList {
	var buckets []*protocol.Bucket
	for _, name := range in {
		buckets = append(buckets, &protocol.Bucket{Name: name})
	}
	return &protocol.BucketList{
		Buckets: buckets,
	}
}

// NFSExportOptionsFromStringToProtocol converts a string containing NFS export options as string to the (now deprecated) protocol message
func NFSExportOptionsFromStringToProtocol(in string) *protocol.NFSExportOptions {
	parts := strings.Split(in, ",")
	out := &protocol.NFSExportOptions{}
	for _, v := range parts {
		v = strings.ToLower(v)
		switch v {
		case "read_only":
			out.ReadOnly = true
		case "root_squash":
			out.RootSquash = true
		case "no_root_squash":
			out.RootSquash = false
		case "secure":
			out.Secure = true
		case "insecure":
			out.Secure = false
		case "async":
			out.Async = true
		case "sync":
			out.Async = false
		case "nohide":
			out.NoHide = true
		case "crossmnt":
			out.CrossMount = true
		case "subtree_check":
			out.SubtreeCheck = true
		case "no_subtree_check":
			out.SubtreeCheck = false
		default:
			logrus.Warnf("unhandled NFS option '%s', ignoring.", v)
		}
	}
	return out
}

// HostSizingFromStringToAbstract converts host sizing requirements from string to *abstract.HostSizingRequirements
func HostSizingRequirementsFromStringToAbstract(in string) (*abstract.HostSizingRequirements, int, fail.Report) {
	tokens, err := parseSizingString(in)
	if err != nil {
		return nil, 0, err
	}

	out := abstract.HostSizingRequirements{}
	if t, ok := tokens["cpu"]; ok {
		min, max, err := t.Validate()
		if err != nil {
			return nil, 0, err
		}
		if min != "" {
			out.MinCores, err = strconv.Atoi(min)
			if err != nil {
				return nil, 0, fail.SyntaxReport("invalid min value '%s' for 'cpu'", min)
			}
		}
		if max != "" {
			out.MaxCores, err = strconv.Atoi(max)
			if err != nil {
				return nil, 0, fail.SyntaxReport("invalid max value '%s' for 'cpu'", max)
			}
		}
	}
	var count int
	if t, ok := tokens["count"]; ok {
		c, _, err := t.Validate()
		if err != nil {
			return nil, 0, err
		}
		count, err = strconv.Atoi(c)
		if err != nil {
			return nil, 0, fail.SyntaxReport("invalid value '%s' for 'count'", c)
		}
	}
	if t, ok := tokens["cpufreq"]; ok {
		min, _, err := t.Validate()
		if err != nil {
			return nil, 0, err
		}
		if min != "" {
			c, err := strconv.ParseFloat(min, 64)
			if err != nil {
				return nil, 0, fail.SyntaxReport("invalid value '%s' for 'cpufreq'", min)
			}
			out.MinCPUFreq = float32(c)
		}
	}
	if t, ok := tokens["gpu"]; ok {
		min, _, err := t.Validate()
		if err != nil {
			return nil, 0, err
		}
		if min != "" {
			out.MinGPU, err = strconv.Atoi(min)
			if err != nil {
				return nil, 0, fail.SyntaxReport("invalid value '%s' for 'gpu'", min)
			}
		}
	} else {
		out.MinGPU = -1
	}
	if t, ok := tokens["ram"]; ok {
		min, max, err := t.Validate()
		if err != nil {
			return nil, 0, err
		}
		if min != "" {
			c, err := strconv.ParseFloat(min, 64)
			if err != nil {
				return nil, 0, fail.SyntaxReport("invalid min value '%s' for 'ram'", min)
			}
			out.MinRAMSize = float32(c)
		}
		if max != "" {
			c, err := strconv.ParseFloat(max, 64)
			if err != nil {
				return nil, 0, fail.SyntaxReport("invalid max value '%s' for 'ram'", max)
			}
			out.MaxRAMSize = float32(c)
		}
	}
	if t, ok := tokens["disk"]; ok {
		min, _, err := t.Validate()
		if err != nil {
			return nil, 0, err
		}
		if min != "" {
			out.MinDiskSize, err = strconv.Atoi(min)
			if err != nil {
				return nil, 0, fail.SyntaxReport("invalid value '%s' for 'disk'", min)
			}
		}
	}
	return &out, count, nil
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
func (t *sizingToken) Push(item string) error {
	if t.IsFull() {
		return fail.NotAvailableReport("token is full")
	}

	item = strings.ToLower(item)
	t.members[t.pos] = item
	t.pos++
	return nil
}

// IsFull tells if the token is full
func (t *sizingToken) IsFull() bool {
	return t.pos >= 3
}

// GetKeyword returns the keyword member of the token (pos == 0)
func (t *sizingToken) GetKeyword() (string, error) {
	if t.pos > 0 {
		return t.members[0], nil
	}
	return "", fail.InvalidRequestReport("keyword is not set in token")
}

// GetOperator returns the operator member of the token (pos == 1)
func (t *sizingToken) GetOperator() (string, error) {
	if t.pos > 1 {
		return t.members[1], nil
	}
	return "", fail.InvalidRequestReport("operator is not set in token")
}

// GetValue returns the value member of the token (pos == 2)
func (t *sizingToken) GetValue() (string, error) {
	if t.pos > 2 {
		return t.members[2], nil
	}
	return "", fail.InvalidRequestReport("value is not set in token")
}

// String returns a string representing the token
func (t *sizingToken) String() string {
	return strings.Join(t.members, " ")
}

// Validate validates value in relation with operator, and returns min and max values if validated
func (t *sizingToken) Validate() (string, string, error) {
	if !t.IsFull() {
		return "", "", fail.InvalidRequestReport("token is not complete")
	}

	keyword := t.members[0]
	operator := t.members[1]
	value := t.members[2]
	switch operator {
	case "~":
		if keyword == "count" {
			return "", "", fail.InvalidRequestReport("'count' can only use '='")
		}

		// "~" means "[<value>-<value*2>]"
		vali, err := strconv.Atoi(value)
		if err != nil {
			valf, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", fail.InvalidRequestReport(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
			return fmt.Sprintf("%.01f", valf), fmt.Sprintf("%.01f", 2*valf), nil
		}
		return fmt.Sprintf("%d", vali), fmt.Sprintf("%d", 2*vali), nil
	case "=":
		if keyword != "count" {
			if value[0] == '[' && value[len(value)-1] == ']' {
				value = value[1 : len(value)-1]
				splitted := strings.Split(value, "-")
				if len(splitted) != 2 {
					return "", "", fail.InvalidRequestReport("value '%s' of '%s' token isn't a valid interval", value, keyword)
				}
				min := splitted[0]
				_, err := strconv.ParseFloat(min, 64)
				if err != nil {
					return "", "", fail.InvalidRequestReport("first value '%s' of interval for token '%s' isn't a valid number: %s", min, keyword, err.Error())
				}
				max := splitted[1]
				_, err = strconv.ParseFloat(max, 64)
				if err != nil {
					return "", "", fail.InvalidRequestReport("second value '%s' of interval for token '%s' isn't a valid number: %s", max, keyword, err.Error())
				}
				return min, max, nil
			}
		}
		_, err := strconv.Atoi(value)
		if err != nil {
			if keyword != "count" {
				_, err = strconv.ParseFloat(value, 64)
			}
			if err != nil {
				return "", "", fail.InvalidRequestReport(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
		}
		return value, value, nil

	case "lt":
		fallthrough
	case "<":
		if keyword == "count" {
			return "", "", fail.InvalidRequestReport("'count' can only use '='")
		}

		vali, err := strconv.Atoi(value)
		if err != nil {
			valf, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", fail.InvalidRequestReport(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
			return "", fmt.Sprintf("%.01f", valf-0.1), nil
		}
		return "", fmt.Sprintf("%d", vali-1), nil

	case "le":
		fallthrough
	case "<=":
		if keyword == "count" {
			return "", "", fail.InvalidRequestReport("'count' can only use '='")
		}

		_, err := strconv.Atoi(value)
		if err != nil {
			_, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", fail.InvalidRequestReport(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
		}
		return "", value, nil

	case "gt":
		fallthrough
	case ">":
		if keyword == "count" {
			return "", "", fail.InvalidRequestReport("'count' can only use '='")
		}

		vali, err := strconv.Atoi(value)
		if err != nil {
			valf, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", fail.InvalidRequestReport(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
			return fmt.Sprintf("%.01f", valf+0.1), "", nil
		}
		return fmt.Sprintf("%d", vali+1), "", nil

	case "ge":
		fallthrough
	case ">=":
		if keyword == "count" {
			return "", "", fail.InvalidRequestReport("'count' can only use '='")
		}

		_, err := strconv.Atoi(value)
		if err != nil {
			_, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return "", "", fail.InvalidRequestReport(fmt.Sprintf("value '%s' of token '%s' isn't a valid number: %s", value, keyword, err.Error()))
			}
		}
		return value, "", nil
	}

	return "", "", fail.InvalidRequestReport(fmt.Sprintf("operator '%s' of token '%s' is not supported", operator, keyword))
}

// parseSizingString transforms a string to a list of tokens
func parseSizingString(request string) (map[string]*sizingToken, fail.Report) {
	var (
		s       scanner.Scanner
		tokens  = map[string]*sizingToken{}
		mytoken *sizingToken
	)
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
			return nil, fail.SyntaxReport("misplace separator ',' at line %d, column %d", p.Line, p.Column)

		case "[": // Manages value in the form [a-b]
			for tok = s.Scan(); tok != scanner.EOF; tok = s.Scan() {
				if s.TokenText() == "]" {
					t += "]"
					break
				}
				t += s.TokenText()
			}

		case "-": // Manages negative number (can be used for gpu)
			for tok = s.Scan(); tok != scanner.EOF; tok = s.Scan() {
				t += s.TokenText()
				break
			}
		}

		if mytoken == nil {
			mytoken = newSizingToken()
		}
		err := mytoken.Push(t)
		if err != nil {
			p := s.Pos()
			return nil, fail.SyntaxReport("invalid content '%s' at line %d, column %d", request, p.Line, p.Column)
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
						return nil, fail.NewReport("invalid content '%s' at line %d, column %d", request, p.Line, p.Column)
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
