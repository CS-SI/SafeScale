GO?=go

.PHONY:	generate clean

vet:
	@$(GO) vet

all:	generate vet

generate: *.go broker_scripts/*
	@$(GO) generate

clean:
	@$(RM) rice-box.go
