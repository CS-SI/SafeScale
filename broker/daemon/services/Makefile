GO?=go

.PHONY:	generate clean

all:	generate 

vet:
	@$(GO) vet

generate: *.go broker_scripts/*
	@$(GO) generate

clean:
	@$(RM) rice-box.go
