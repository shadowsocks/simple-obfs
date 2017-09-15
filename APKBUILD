# Contributor: Max Lv <max.c.lv@gmail.com>
# Maintainer: Max Lv <max.c.lv@gmail.com>
pkgname=simple-obfs
pkgver=0.0.3
pkgrel=1
pkgdesc="Simple-obfs is a simple obfusacting tool, designed as plugin server of shadowsocks."
url="https://github.com/shadowsocks/simple-obfs"
arch="all"
license="GPL3"
depends="libtool libev-dev c-ares-dev linux-headers"
makedepends="gcc autoconf make automake zlib-devel openssl asciidoc xmlto libpcre32 g++"
source="https://github.com/shadowsocks/simple-obfs/archive/v$pkgver.tar.gz"
sha512sums="1e2f1c5a32508426a58d4894a3623d10ff6add875137444cea9bda61d972f3d36bd8b477358f31e719a9950fc745cebff2c632b4fca117cc439a69a747b85837  simple-obfs-0.0.3.tar.gz"
builddir="$srcdir"/simple-obfs-$pkgver

build() {
	cd "$builddir"
	./autogen.sh
	./configure                       
	make                                                
}

package() {
	cd "$builddir"
	make DESTDIR="$pkgdir" install
}
