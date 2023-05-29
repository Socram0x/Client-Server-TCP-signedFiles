#!/bin/bash

# current path of the script
current_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Name of the binary
binary_name="server"

# Compile and generate the binary
go build -o "$current_dir/$binary_name" "$current_dir/cmd/server/server.go"

# Verify the compilation
if [ $? -eq 0 ]; then
  echo "Binary OK: $current_dir/$binary_name"
else
  echo "Error: Binary NOK."
fi
