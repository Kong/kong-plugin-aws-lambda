# this runs inside the Kong container when it starts

luarocks remove kong-plugin-aws-lambda --force

# install pre-fetched private dependencies
cd /kong-plugin/lua-resty-http
luarocks remove lua-resty-http --force
luarocks make

# install public dependencies
find /kong-plugin -maxdepth 1 -type f -name '*.rockspec' -exec luarocks install --only-deps {} \;
