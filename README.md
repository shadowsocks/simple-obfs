# simple-obfs

## Intro

Simple-obfs is a simple obfusacting tool, designed
as plugin server of shadowsocks.

Current version: 0.0.2 | [Changelog](Changes)

## Build

For Unix-like systems, especially Debian-based systems,
e.g. Ubuntu, Debian or Linux Mint, you can build the binary like this:

```bash
# Debian / Ubuntu
sudo apt-get install --no-install-recommends build-essential autoconf libtool libssl-dev libpcre3-dev asciidoc xmlto
# CentOS / Fedora / RHEL
sudo yum install gcc autoconf libtool automake make zlib-devel openssl-devel asciidoc xmlto
# Arch
sudo pacman -Syu gcc autoconf libtool automake make zlib openssl asciidoc xmlto
./configure && make
sudo make install
```
## Usage

For a detailed and complete list of all supported arguments, you may refer to the
man pages of the applications, respectively.

### Example (plugin mode with shadowsocks)

Add respective item to `--plugin` and `--plugin-opts` arg or as value of `plugin` and `plugin_opts` in JSON.

One the client:

```bash
ss-local -c config.json --plugin obfs-local --plugin-opts "obfs=http;obfs-host=www.bing.com"
```

On the server:

```bash
ss-server -c config.json --plugin obfs-server --plugin-opts "obfs=http"
```

### Example (standalone mode)

On the client:

```bash
obfs-local -s server_ip -p 8139 -l 1984 --obfs http --obfs-host www.bing.com
ss-local -c config.json -s 127.0.0.1 -p 1984 -l 1080
```

On the server:

```bash
obfs-server -s server_ip -p 8139 --obfs http -r 127.0.0.1:8388
ss-server -c config.json -s 127.0.0.1 -p 8388
```

## License

Copyright (C) 2016 Max Lv <max.c.lv@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
