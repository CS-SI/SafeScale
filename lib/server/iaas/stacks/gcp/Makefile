GO?=go

.PHONY:	generate clean test

all:	#generate

vet:
	@$(GO) vet ./...

generate: clean
	@$(GO) generate > /dev/null 2>&1

test:
	@$(GO) test $(RACE_CHECK_TEST) -v ./...

clean:
	@$(RM) rice-box.go || true


