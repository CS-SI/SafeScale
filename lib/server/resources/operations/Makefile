include ../../../../common.mk

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@(cd features ; make $(@))
	@(cd clusters ; make $(@))

vet:
	@$(GO) vet ./...

clean: 
	@(cd features ; make $(@))
	@(cd clusters ; make $(@))
	@$(RM) rice-box.go
