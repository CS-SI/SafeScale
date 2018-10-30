GO?=go

.PHONY:	clean test

all: generate

generate:
	@$(GO) generate

vet:
	@$(GO) vet ./...

test:
	@$(GO) test

clean:
	@($(RM) rice-box.go || true)

