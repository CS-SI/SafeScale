GO?=go

.PHONY: clean retry cli

all: utils retry cli

utils: *.go
	@$(GO) generate ./...

cli:
	@(cd cli && $(MAKE))

retry:
	@(cd retry && $(MAKE))

clean:
	@(cd cli && $(MAKE) $@)
	@(cd retry && $(MAKE) $@)
