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
source="https://github.com/shadowsocks/simple-obfs/archive/v$pkgver.tar.gz
	https://github.com/shadowsocks/libcork/archive/shadowsocks.zip"
sha512sums="1e2f1c5a32508426a58d4894a3623d10ff6add875137444cea9bda61d972f3d36bd8b477358f31e719a9950fc745cebff2c632b4fca117cc439a69a747b85837  simple-obfs-0.0.3.tar.gz
143365f007242c8f5e009f75d03bcc8a4dd55edbdb0b357b0ae76e802a4c3847be3b1b5c93aacb643c5b46b4a102d7dfe8b235ff205e933884e0b983ba7bb1ad  libcork-shadowsocks.zip"
builddir="$srcdir"/simple-obfs-$pkgver
includeddir="$srcdir"/libcork-shadowsocks

prepare() {
	mv -f $includeddir $builddir/libcork
}

build() {
	cd "$builddir"
	./autogen.sh
	./configure \
        --disable-documentation
	make                                                
}

package() {
	cd "$builddir"
	make DESTDIR="$pkgdir" install
}
