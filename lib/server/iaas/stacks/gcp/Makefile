GO?=go

.PHONY:	generate clean test

all:	generate

vet:
	@$(GO) vet ./...

generate: clean
	@$(GO) generate

test:
	@$(GO) test

clean:
	@$(RM) rice-box.go || true


