all: scanner

scanner: scanner.go
	go generate && go build

.PHONY: clean

clean:
	@(rm scanner)

