GO?=go

.PHONY:	generate clean test

all:	generate

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate > /dev/null 2>&1

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -v ./...

clean: ;


