package net

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry"
	"github.com/stretchr/testify/assert"
)

type MyError struct {
	error
	temporal bool
}

func NewMyError(error error, temporal bool) *MyError {
	return &MyError{error: error, temporal: temporal}
}

func (e MyError) Timeout() bool {
	return true
}

func (e MyError) Temporary() bool {
	return e.temporal
}

func (e MyError) Error() string {
	return ""
}

func Test_normalizeErrorAndCheckIfRetriable(t *testing.T) {
	type args struct {
		in  error
		out error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"std error", args{in: fmt.Errorf("something"), out: retry.StopRetryError(fmt.Errorf("something"))}, true},
		{
			"not avail", args{in: fail.NotAvailableError("nice try"), out: fmt.Errorf("nice try")}, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := normalizeErrorAndCheckIfRetriable(tt.args.in); (err != nil) != tt.wantErr || (err != tt.args.out) {
				if err != nil && err != tt.args.out {
					if !assert.ObjectsAreEqualValues(err.Error(), tt.args.out.Error()) {
						t.Errorf("normalizeErrorAndCheckIfRetriable() wanted = '%v', actually = '%v'", tt.args.out, err)
					}
				}
				if (err != nil) != tt.wantErr {
					t.Errorf("normalizeErrorAndCheckIfRetriable() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			if urr := oldNormalizeErrorAndCheckIfRetriable(tt.args.in); (urr != nil) != tt.wantErr || (urr != tt.args.out) {
				if urr != nil && urr != tt.args.out {
					if !assert.ObjectsAreEqualValues(urr.Error(), tt.args.out.Error()) {
						t.Errorf("oldNormalizeErrorAndCheckIfRetriable() wanted = '%v', actually = '%v'", tt.args.out, urr)
					}
				}
				if (urr != nil) != tt.wantErr {
					t.Errorf("oldNormalizeErrorAndCheckIfRetriable() error = %v, wantErr %v", urr, tt.wantErr)
				}
			}
		})
	}
}

func Test_normalizeErrorImprovedAndCheckIfRetriable(t *testing.T) {
	type args struct {
		in  error
		out error
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"temporal net error", args{in: NewMyError(fmt.Errorf("encrypted"), true), out: NewMyError(fmt.Errorf("encrypted"), true)}, true},
		{"final net error", args{in: NewMyError(fmt.Errorf("encrypted"), false), out: retry.StopRetryError(NewMyError(fmt.Errorf("encrypted"), false))}, true},
		{"crafted url error", args{in: &url.Error{
			Op:  "something",
			URL: "www.google.com",
			Err: nil,
		}, out: retry.StopRetryError(&url.Error{
			Op:  "something",
			URL: "www.google.com",
			Err: nil,
		})}, true},
		{"crafted url error with reason", args{in: &url.Error{
			Op:  "something",
			URL: "www.google.com",
			Err: fmt.Errorf("it was DNS"),
		}, out: retry.StopRetryError(&url.Error{
			Op:  "something",
			URL: "www.google.com",
			Err: fmt.Errorf("it was DNS"),
		})}, true},
		{
			"not avail", args{in: fail.NotAvailableError("nice try"), out: fmt.Errorf("nice try")}, true,
		},
		{
			"not avail ptr", args{in: *fail.NotAvailableError("nice try"), out: fmt.Errorf("nice try")}, true,
		},
		{
			"not avail with cause", args{in: fail.NotAvailableErrorWithCause(fmt.Errorf("out of time"), "nice try"), out: retry.StopRetryError(fmt.Errorf("nice try: out of time"))}, true,
		},
		{
			"not avail ptr with cause", args{in: *fail.NotAvailableErrorWithCause(fmt.Errorf("out of time"), "nice try"), out: retry.StopRetryError(fmt.Errorf("nice try: out of time"))}, true,
		},
		{
			"overflow", args{in: fail.OverflowError(nil, 0, "nice try"), out: fmt.Errorf("nice try")}, true,
		},
		{
			"overflow ptr", args{in: *fail.OverflowError(nil, 0, "nice try"), out: fmt.Errorf("nice try")}, true,
		},
		{
			"overflow with cause", args{in: fail.OverflowError(fmt.Errorf("nice try"), 0, "ouch"), out: retry.StopRetryError(fmt.Errorf("ouch: nice try"))}, true,
		},
		{
			"overflow ptr with cause", args{in: *fail.OverflowError(fmt.Errorf("nice try"), 0, "ouch"), out: retry.StopRetryError(fmt.Errorf("ouch: nice try"))}, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := normalizeErrorAndCheckIfRetriable(tt.args.in); (err != nil) != tt.wantErr || (err != tt.args.out) {
				if err != nil && err != tt.args.out {
					if !assert.ObjectsAreEqualValues(err.Error(), tt.args.out.Error()) {
						t.Errorf("normalizeErrorAndCheckIfRetriable() wanted = '%v', actually = '%v'", tt.args.out, err)
					}
				}
				if (err != nil) != tt.wantErr {
					t.Errorf("normalizeErrorAndCheckIfRetriable() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}
