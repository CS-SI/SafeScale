GO?=go

.PHONY:	generate clean

all:	generate vet

vet:
	@$(GO) vet
	@$(GO) vet ./HostAdditionalInfo
	@$(GO) vet ./IPVersion
	@$(GO) vet ./HostState
	@$(GO) vet ./VolumeSpeed
	@$(GO) vet ./VolumeState

DIRECTORIES := $(sort $(dir $(wildcard */)))

generate:
	@(for d in $(DIRECTORIES); do (cd $$d; $(GO) generate); done)

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(RM) *_string.go); done)