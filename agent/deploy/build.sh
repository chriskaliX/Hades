#!/bin/bash
set -e

# install nfpm
if ! nfpm -v > /dev/null 2>&1;then
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
fi

# release both arch
for arch in amd64 arm64; do
    export GOARCH=${arch}
    sed -i 's/version:.*$/version: '${BUILD_VERSION}'/g' nfpm.yaml
    sed -i 's/arch:.*$/arch: '${arch}'/g' nfpm.yaml
    make deb
    make rpm
done