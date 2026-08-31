#!/usr/bin/env bash
# scripts/gen_proto.sh — Generate Python gRPC stubs from proto/vpnd.proto
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTO_DIR="$REPO_ROOT/proto"
PROTO_FILE="$PROTO_DIR/vpnd.proto"

if [[ ! -f "$PROTO_FILE" ]]; then
  echo "ERROR: proto file not found: $PROTO_FILE" >&2
  exit 1
fi

# Check grpc_tools is installed
if ! python3 -c "import grpc_tools" 2>/dev/null; then
  echo "Installing grpcio-tools..."
  pip3 install grpcio-tools
fi

echo "Generating Python stubs..."
for TARGET in client-gui admin-gui; do
  OUT_DIR="$REPO_ROOT/$TARGET"
  mkdir -p "$OUT_DIR"
  python3 -m grpc_tools.protoc \
    -I "$PROTO_DIR" \
    --python_out="$OUT_DIR" \
    --grpc_python_out="$OUT_DIR" \
    "$PROTO_FILE"
  echo "  → $OUT_DIR/vpnd_pb2.py"
  echo "  → $OUT_DIR/vpnd_pb2_grpc.py"
done

echo "Done."
