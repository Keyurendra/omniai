#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

: "${CODEGEN_PKG:=_output/tmp/code-generator}"
CODEGEN_PKG="$(realpath $CODEGEN_PKG)"

source "$CODEGEN_PKG/kube_codegen.sh"
kube::codegen::gen_client . \
   --with-watch \
   --output-dir pkg/generated \
   --output-pkg github.com/accuknox/omniscan/pkg/generated \
   --boilerplate hack/boilerplate.go.txt
