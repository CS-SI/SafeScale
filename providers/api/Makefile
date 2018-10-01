GO?=go

.PHONY:	clean filters

vet:
	@$(GO) vet ./...

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(MAKE) clean); done)
