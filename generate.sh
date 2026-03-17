#!/bin/bash
set -ex

OUTPUT_DIR="/out/Proto"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

PROTO_INCLUDES="-I /workspace/sigstore-protobuf-specs/protos 
                -I /workspace/googleapis"

# Find all proto files in sigstore-protobuf-specs
SIGSTORE_PROTOS=$(find /workspace/sigstore-protobuf-specs/protos -name "*.proto")

# Generate PHP for Sigstore protos
protoc $PROTO_INCLUDES --php_out="$OUTPUT_DIR" $SIGSTORE_PROTOS

echo "PHP classes generated in $OUTPUT_DIR"