GO?=go

all: scanner

scanner: scanner.go
	$(GO) generate && $(GO) build

.PHONY: clean

clean:
	@($(RM) scanner)

