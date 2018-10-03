GO?=go

.PHONY:	clean generate

DIRECTORIES := $(sort $(dir $(wildcard */)))

all:	generate

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate ./...

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(MAKE) clean); done)