GO?=go

.PHONY:	clean test

all: generate

generate:
	@$(GO) generate > /dev/null 2>&1

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -v ./...
