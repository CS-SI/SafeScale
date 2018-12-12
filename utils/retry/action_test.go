/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package retry

import (
	"fmt"
	"testing"
	"time"
)

func quick_sleepy() error {
	fmt.Println("Quick OK")
	time.Sleep(1 * time.Second)
	return nil
}

func sleepy() error {
	fmt.Println("Slow OK")
	time.Sleep(1 * time.Minute)
	return nil
}

func sleepy_failure() error {
	fmt.Println("Slow fail")
	time.Sleep(1 * time.Minute)
	return fmt.Errorf("Always fails...")
}

func quick_sleepy_failure() error {
	fmt.Println("Quick fail")
	time.Sleep(1 * time.Second)
	return fmt.Errorf("Always fails...")
}


func TestWhileUnsuccessfulDelay5Seconds(t *testing.T) {
	type args struct {
		run     func() error
		timeout time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{"OneTimeSlowOK", args{sleepy, time.Duration(15) * time.Second }, false},
		{"OneTimeSlowFails", args{sleepy_failure, time.Duration(15) * time.Second }, true},
		{"OneTimeQuickOK", args{quick_sleepy, time.Duration(15) * time.Second }, false},
		{"UntilTimeouts", args{quick_sleepy_failure, time.Duration(15) * time.Second }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := WhileUnsuccessfulDelay5Seconds(tt.args.run, tt.args.timeout); (err != nil) != tt.wantErr {
				t.Errorf("WhileUnsuccessfulDelay5Seconds() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}


func TestWhileUnsuccessfulDelay5SecondsCheck(t *testing.T) {
	type args struct {
		run     func() error
		timeout time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{"OneTimeSlowOK", args{sleepy, time.Duration(15) * time.Second }, false},
		{"OneTimeSlowFails", args{sleepy_failure, time.Duration(15) * time.Second }, true},
		{"OneTimeQuickOK", args{quick_sleepy, time.Duration(15) * time.Second }, false},
		{"UntilTimeouts", args{quick_sleepy_failure, time.Duration(15) * time.Second }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testStart := time.Now()
			if err := WhileUnsuccessfulDelay5Seconds(tt.args.run, tt.args.timeout); (err != nil) != tt.wantErr {
				t.Errorf("WhileUnsuccessfulDelay5Seconds() error = %v, wantErr %v", err, tt.wantErr)
			}
			delta := time.Since(testStart)
			if delta.Seconds() >= tt.args.timeout.Seconds() {
				t.Errorf("WhileUnsuccessfulDelay5Seconds() error = %v", fmt.Errorf("It's not a real timeout, il tasted %f and the limit was %f", delta.Seconds(), tt.args.timeout.Seconds()))
			}
		})
	}
}
