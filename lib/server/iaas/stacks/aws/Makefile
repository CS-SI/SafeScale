GO?=go

.PHONY:	generate clean test

all:	generate

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate > /dev/null 2>&1

test:
	@$(GO) test -race -v ./...

clean:
	@$(RM) rice-box.go || true


