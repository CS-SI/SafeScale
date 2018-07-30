
GO?=go

all: generate vet

.PHONY: vet generate clean

SUBDIRS := $(sort $(dir $(wildcard */)))

vet:
	@$(GO) vet
	@(for d in $(SUBDIRS); do (cd $$d; $(GO) vet ); done)

generate:
	@(for d in $(SUBDIRS); do (cd $$d; $(GO) generate); done)

clean:
	@(for d in $(SUBDIRS); do (cd $$d; $(RM) *_string.go); done)
