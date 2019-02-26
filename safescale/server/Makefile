GO?=go

.PHONY:	cluster handlers install clean

all:	cluster handlers install

vet:
	@$(GO) vet ./...

cluster:
	@(cd cluster && $(MAKE))

handlers:
	@(cd handlers && $(MAKE))

install:
	@(cd install && $(MAKE))

clean:
	@(cd handlers && $(MAKE) $@)
	@(cd cluster && $(MAKE) $@)
	@(cd install && $(MAKE) $@)
	@$(RM) ./mocks/*.go || true
