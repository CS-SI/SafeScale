GO?=go

.PHONY:	generate clean test

all:	generate vet

vet:
	#@$(GO) vet
	@$(GO) vet ./s3

generate:
	@$(GO) generate

test:
	@$(GO) test

clean:
	@($(RM) rice-box.go)

