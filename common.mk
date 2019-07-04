VERSION=19.12.0-alpha
export VERSION

ifeq ($(MAKE_LEVEL),)
MAKE_LEVEL=-1
MAKE_TRACE=""
else
MAKE_LEVEL+=1
MAKE_TRACE=$(shell printf '    %.0s' {1..$(MAKE_LEVEL)})
endif
export MAKE_LEVEL


ifndef VERBOSE
MAKEFLAGS += --no-print-directory
endif

FIRSTUPDATE := $(shell git remote update >/dev/null 2>&1)
BUILD := $(shell git rev-parse HEAD)
UPSTREAM := $(shell git rev-parse origin/develop)
LOCAL := $(shell git rev-parse HEAD)
REMOTE := $(shell git rev-parse $(UPSTREAM))
BASE := $(shell git merge-base HEAD $(UPSTREAM))

GO?=go
CP?=cp
RM?=rm
BROWSER?=firefox

ifeq ($(OS),Windows_NT)
HOME := $(shell printf "%b" "$(HOME)" 2>/dev/null | tr '\' '/' > .tmpfile 2>/dev/null && cat .tmpfile && $(RM) .tmpfile)
ifeq (, $(shell which rm))
RM = del /Q
endif
endif

GOPATH?=$(HOME)/go
GOBIN?=$(GOPATH)/bin
CIBIN?=/tmp

ifeq (, $(shell which git))
$(error "No git in your PATH: [$(PATH)], you must have git installed and available through your PATH")
endif

ifeq (, $(GOPATH))
$(error "No GOPATH defined")
endif

# Handling multiple gopath: use ~/go by default
ifeq ($(findstring :,$(GOBIN)),:)
GOBIN=$(HOME)/go/bin
endif

# Handling multiple gopath: use $(HOME)/go by default
ifeq ($(findstring :,$(GOPATH)),:)
GOINCLUDEPATH=$(HOME)/go
else
GOINCLUDEPATH=$(GOPATH)
endif

ifeq ($(strip $(GOPATH)),)
GOINCLUDEPATH=$(HOME)/go
endif

ifneq ($(OS),Windows_NT)
PATH = $(HOME)/.local/bin:$(shell printenv PATH)
endif

ifneq ($(OS),Windows_NT)
ifneq ($(findstring $(GOBIN),$(PATH)),$(GOBIN))
$(error "Your 'GOBIN' directory [$(GOBIN)] must be included in your 'PATH' [$(PATH)]")
endif
endif

# Life is better with colors
COM_COLOR   = \033[0;34m
OBJ_COLOR   = \033[0;36m
OK_COLOR    = \033[0;32m
GOLD_COLOR  = \033[0;93m
ERROR_COLOR = \033[0;31m
WARN_COLOR  = \033[0;33m
NO_COLOR    = \033[m

OK_STRING    = "[OK]"
INFO_STRING  = "[INFO]"
ERROR_STRING = "[ERROR]"
WARN_STRING  = "[WARNING]"

BUILD_TAGS = ""
export BUILD_TAGS
