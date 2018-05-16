GO?=go

.PHONY:	generate clean

all:	generate

generate: *.go broker_scripts/*
	@$(GO) generate

clean:
	@$(RM) rice-box.go
