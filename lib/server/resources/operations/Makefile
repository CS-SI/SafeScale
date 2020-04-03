include ../../../../common.mk

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@(cd clusterflavors ; $(MAKE) $(@))
	@$(GO) generate -run rice

vet:
	@$(GO) vet ./...

clean:
	@(cd clusterflavors ; $(MAKE) $(@))
	@$(RM) rice-box.go
