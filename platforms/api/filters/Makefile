GO?=go

.PHONY: vet

all: 

DIRECTORIES := $(sort $(dir $(wildcard */)))

vet:
	@(for d in $(DIRECTORIES); do (cd $$d; $(GO) vet); done)