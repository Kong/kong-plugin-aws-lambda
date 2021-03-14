#!/usr/bin/env bash

# this runs on the host, before the Kong container is started


if pushd lua-resty-http > /dev/null; then
  git checkout master
  git pull

else
  git clone https://github.com/ledgetech/lua-resty-http.git || exit 1
  pushd lua-resty-http  > /dev/null
fi

popd > /dev/null
