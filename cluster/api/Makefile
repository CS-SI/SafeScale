all: enums

.PHONY: enums clean

enums: ClusterState/enum_string.go Complexity/enum_string.go Flavor/enum_string.go NodeState/enum_string.go NodeType/enum_string.go

ClusterState/enum_string.go: ClusterState/enum.go
	@(cd ClusterState && go generate)

Complexity/enum_string.go: Complexity/enum.go
	@(cd Complexity && go generate)

Flavor/enum_string.go: Flavor/enum.go
	@(cd Flavor && go generate)

NodeState/enum_string.go: NodeState/enum.go
	@(cd NodeState && go generate)

NodeType/enum_string.go: NodeType/enum.go
	@(cd NodeType && go generate)

clean:
	@(rm -f ClusterState/enum_string.go)
	@(rm -f Complexity/enum_string.go)
	@(rm -f Flavor/enum_string.go)
	@(rm -f NodeState/enum_string.go)
	@(rm -f NodeType/enum_string.go)
