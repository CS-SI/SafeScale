#!/bin/bash

go test -v -timeout 14400s -tags=allintegration ./... | tee test_results.log
