GO?=go

.PHONY: clean retry

all: utils retry

utils: *.go
	@go generate

retry:
	@(cd retry && $(MAKE))

clean:
	@(cd retry && $(MAKE) $@)
