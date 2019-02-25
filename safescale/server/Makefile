GO?=go
EXEC:=safescaled

.PHONY:	safescaled handlers clean

all:	safescaled

vet:
	@$(GO) vet ./...

safescaled: handlers main.go commands/*.go ../utils/*.go ../safescale.pb.go
	@$(GO) build -race -o $(EXEC) $(BUILD_TAGS)

handlers:
	@(cd handlers && $(MAKE))

clean:
	@(cd handlers && $(MAKE) $@)
	@$(RM) $(EXEC) || true
	@$(RM) ./mocks/*.go || true
