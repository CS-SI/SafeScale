include ../../../../common.mk

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@$(GO) generate -run rice .

vet:
	@$(GO) vet ./...

clean:
	@$(RM) rice-box.go
