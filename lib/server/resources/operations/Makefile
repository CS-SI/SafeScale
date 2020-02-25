include ../../../../common.mk

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@(cd clusterflavors ; make $(@))

vet:
	@$(GO) vet ./...

clean: 
	@(cd clusterflavors ; make $(@))
	@$(RM) rice-box.go
