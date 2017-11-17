# Contributor: Max Lv <max.c.lv@gmail.com>
# Maintainer: Max Lv <max.c.lv@gmail.com>
pkgname=simple-obfs
pkgver=0.0.5
pkgrel=0
pkgdesc="Simple-obfs is a simple obfusacting tool, designed as plugin server of shadowsocks."
url="https://github.com/shadowsocks/simple-obfs"
arch="all"
license="GPLv3+"
makedepends="autoconf automake libtool linux-headers libev-dev asciidoc xmlto"
subpackages="$pkgname-doc"
builddir="$srcdir/$pkgname"

prepare() {
	cd "$srcdir"
	git clone "$url"
	cd "$builddir"
	git checkout "v$pkgver"
	git submodule update --init --recursive
}

build() {
	cd "$builddir"
	./autogen.sh
	./configure --prefix=/usr
	make
}

check() {
	cd "$builddir"
	make check
}

package() {
	cd "$builddir"
	make DESTDIR="$pkgdir" install
}
