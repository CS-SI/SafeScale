GO?=go

all: scanner vet

vet:
	@$(GO) vet

scanner: scanner.go
	$(GO) generate && $(GO) build

.PHONY: clean

clean:
	@($(RM) scanner)

