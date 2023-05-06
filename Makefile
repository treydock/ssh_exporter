# Needs to be defined before including Makefile.common to auto-generate targets
DOCKER_ARCHS ?= amd64 armv7 arm64 ppc64le s390x
DOCKER_REPO	 ?= treydock
export GOPATH ?= $(firstword $(subst :, ,$(shell go env GOPATH)))

include Makefile.common

DOCKER_IMAGE_NAME ?= ssh_exporter

coverage:
	go test -race -coverpkg=./... -coverprofile=coverage.txt -covermode=atomic ./...
