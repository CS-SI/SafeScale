GO?=go

.PHONY:	safescale safescaled clean vet

all:	safescale safescaled

vet:
	@(cd safescale && $(MAKE) $@)
	@(cd safescaled && $(MAKE) $@)

safescale:
	@(cd safescale && $(MAKE))

safescaled:
	@(cd safescaled && $(MAKE))

clean:
	@(cd safescale && $(MAKE) $@)
	@(cd safescaled && $(MAKE) $@)
