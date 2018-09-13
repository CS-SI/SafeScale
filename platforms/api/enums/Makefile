GO?=go

.PHONY:	generate clean vet 

all:	generate 

vet:
	@(for d in $(DIRECTORIES); do (cd $$d; $(GO) vet); done)

DIRECTORIES := $(sort $(dir $(wildcard */)))

generate:
	@(for d in $(DIRECTORIES); do (cd $$d; $(GO) generate); done)

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(RM) *_string.go); done)