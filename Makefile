SHELL := /bin/bash

.PHONY: all clean run
all: tun

BUILDDIR ?= build

tun: tidy $(BUILDDIR)
	go build -o $(BUILDDIR) ./cmd/tun

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

.PHONY: tidy
tidy:
	go fmt ./...
	go mod tidy -v

.PHONY: test
test:
	go test -v -race -buildvcs ./...

clean:
	rm -f $(BUILDDIR)/tun

run: tun
	$(BUILDDIR)/tun

.PHONY: tunup
tunup:
	ifconfig utun4 10.1.0.30 10.1.0.40 up
