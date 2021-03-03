GO?=go

.PHONY:	generate clean test

all:	generate

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate

test:
	@$(GO) test -race -v ./...

clean:
	@$(RM) rice-box.go || true


