#!/usr/bin/env bash

PLUGIN_FOLDER=..

# pick a plugin repo, and pack the rock, and its dependencies (clear first)
# because we use a local LuaRocks repo, we also need the dependencies in there
# since the public one will not be available
pushd $PLUGIN_FOLDER
luarocks remove kong-oidc --force
luarocks remove lua-resty-openidc --force
luarocks remove lua-resty-jwt --force
luarocks make
luarocks pack kong-oidc
luarocks pack lua-resty-openidc
luarocks pack lua-resty-jwt
popd

# create a LuaRocks repo, and copy the rocks in there. This directory will be
# used as the base LuaRocks server we're installing from. These, and only these,
# rocks can be installed.
rm -rf ./rocksdir
mkdir ./rocksdir
mv $PLUGIN_FOLDER/*.rock ./rocksdir/

#build the custom image
docker build \
   --build-arg "KONG_LICENSE_DATA=$KONG_LICENSE_DATA" \
   --build-arg KONG_BASE="kong:2.1.0" \
   --build-arg PLUGINS="kong-oidc" \
   --build-arg ROCKS_DIR="./rocksdir" \
   --tag "kong-oidc:2.1" .


