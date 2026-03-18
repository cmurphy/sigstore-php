#!/bin/bash
set -ex

OUTPUT_DIR="/out/Proto"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Proto includes for sigstore and google apis
PROTO_INCLUDES="-I /workspace/sigstore-protobuf-specs/protos 
                -I /workspace/googleapis"

# Find all proto files in sigstore-protobuf-specs
SIGSTORE_PROTOS=$(find /workspace/sigstore-protobuf-specs/protos -name "*.proto")

# Specific Google API protos that are imported by sigstore protos
GOOGLE_API_PROTOS="/workspace/googleapis/google/api/field_behavior.proto 
                   /workspace/googleapis/google/api/annotations.proto 
                   /workspace/googleapis/google/api/http.proto 
                   /workspace/googleapis/google/api/client.proto"

# Check if Google API files exist
for proto_file in $GOOGLE_API_PROTOS; do
  if [ ! -f "$proto_file" ]; then
    echo "Error: Required Google API proto file not found: $proto_file"
    exit 1
  fi
done

# Generate PHP for all protos
# Well-known types like timestamp.proto are included in protoc
protoc $PROTO_INCLUDES --php_out="$OUTPUT_DIR" $SIGSTORE_PROTOS $GOOGLE_API_PROTOS

echo "PHP classes generated in $OUTPUT_DIR"