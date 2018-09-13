GO?=go

.PHONY:	generate clean test

all:	generate 

vet:
	@$(GO) vet

generate:
	@$(GO) generate
	
test:
	$(GO) test
	
clean:
	@($(RM) rice-box.go)

