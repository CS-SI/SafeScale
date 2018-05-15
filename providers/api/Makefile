all:	generate

.PHONY:	generate clean

DIRECTORIES = $(sort $(dir $(wildcard */)))

generate:
	@(for d in $(DIRECTORIES); do (cd $$d; go generate); done)
	
clean:
	@(for d in $(DIRECTORIES); do (cd $$d; rm -f *_string.go); done)
