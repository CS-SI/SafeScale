GO?=go

.PHONY: clean retry cli

all: utils retry cli

utils: *.go
	@go generate

cli:
	@(cd cli && $(MAKE))

retry:
	@(cd retry && $(MAKE))

clean:
	@(cd retry && $(MAKE) $@)
