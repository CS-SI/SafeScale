GO?=go

.PHONY:	generate clean

all:	generate 

vet:
	@$(GO) vet
	@$(GO) vet ./Method

DIRECTORIES := $(sort $(dir $(wildcard */)))

generate:
	@(for d in $(DIRECTORIES); do (cd $$d; $(GO) generate); done)

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(RM) *_string.go); done)
