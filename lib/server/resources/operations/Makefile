include ../../../../common.mk

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@(cd feature ; make $(@))
	@(cd cluster ; make $(@))

vet:
	@$(GO) vet ./...

clean: 
	@(cd feature ; make $(@))
	@(cd cluster ; make $(@))
	@$(RM) rice-box.go
