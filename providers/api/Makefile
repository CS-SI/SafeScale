GO?=go

.PHONY:	clean enums

DIRECTORIES := $(sort $(dir $(wildcard */)))

all:	enums 

vet:
	@$(GO) vet ./...

enums:
	@$(GO) generate ./...

generate:
	@$(GO) generate ./...

clean:
	@(cd enums && $(MAKE) $@)
	@(for d in $(DIRECTORIES); do (cd $$d; $(MAKE) clean); done)