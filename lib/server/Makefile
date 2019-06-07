GO?=go

.PHONY:	cluster handlers iaas install clean vet

all:	iaas cluster handlers install

generate:
	@(cd iaas && $(MAKE) $@)
	@(cd cluster && $(MAKE) $@)
	@(cd install && $(MAKE) $@)

vet:
	@$(GO) vet ./...

iaas:
	@(cd iaas && $(MAKE))

cluster:
	@(cd cluster && $(MAKE))

handlers:
	@(cd handlers && $(MAKE))

install:
	@(cd install && $(MAKE))

clean:
	@(cd iaas && $(MAKE) $@)
	@(cd handlers && $(MAKE) $@)
	@(cd cluster && $(MAKE) $@)
	@(cd install && $(MAKE) $@)
	@$(RM) ./mocks/*.go || true
