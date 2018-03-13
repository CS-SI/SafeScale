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
