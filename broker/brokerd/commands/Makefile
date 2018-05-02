all:	generate

.PHONY:	generate clean

generate: *.go broker_scripts/*
	@go generate

clean:
	@rm -f rice-box.go
