all: openstack

.PHONY: api openstack clean

openstack: *.go
	go generate

clean:
	@rm -f rice-box.go

