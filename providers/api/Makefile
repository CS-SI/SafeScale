GO?=go

.PHONY:	enums clean filters

all:	enums 

vet:
	@$(GO) vet ./...

enums:
	@(cd $@; $(MAKE) generate)

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(MAKE) clean); done)