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

package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/mjibson/go-dsp/fft"
)

func main() {
	runtime.GOMAXPROCS(1)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		data := make([]complex128, 10001)
		for i := range data {
			// Fill data
			data[i] = complex(float64(i*2)/float64(10001), 0)
		}
		fft.FFT(data)
	}
	t := time.Now()
	elapsed := t.Sub(start)
	fmt.Println(5.0 / elapsed.Seconds())
}
