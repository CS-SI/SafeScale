GO?=go

.PHONY:	generate clean test

all:	generate 

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate -tags libvirt
	
test:
	$(GO) test


