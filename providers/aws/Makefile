all: aws

.PHONY: clean

aws: *.go s3/*.go scripts/*
	go generate

clean:
	@rm -f rice-box.go

