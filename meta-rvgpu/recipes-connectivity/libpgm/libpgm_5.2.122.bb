SUMMARY = "OpenPGM shared library"
DESCRIPTION = "\
	OpenPGM is an open source implementation of the Pragmatic General Multicast \
	(PGM) specification in RFC 3208 available at www.ietf.org. PGM is a reliable\
	and scalable multicast protocol that enables receivers to detect loss,\
	request retransmission of lost data, or notify an application of\
	unrecoverable loss. PGM is a receiver-reliable protocol, which means the\
	receiver is responsible for ensuring all data is received, absolving the\
	sender of reception responsibility. PGM runs over a best effort datagram\
	service, currently OpenPGM uses IP multicast but could be implemented above\
	switched fabrics such as InfiniBand.\
	"

LICENSE = "LGPLv2.1+"
LIC_FILES_CHKSUM = "file://COPYING;md5=fbc093901857fcd118f065f900982c24"

SRC_URI[md5sum] = "d7673e9ff6cc33cf42fe9fb9a7bfbffa"
SRC_URI[sha256sum] = "6b895f550b95284dcde7189b01e04a9a1c1f94579af31b1eebd32c2207a1ba2c"

SRC_URI = "https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/openpgm/libpgm-${PV}.tar.gz \
	   file://0001-openpgm-fix-cross-compilation-error.patch \
	   file://0002-openpgm-remove-tests.patch \
	   "

S = "${WORKDIR}/libpgm-${PV}/openpgm/pgm"

inherit autotools pkgconfig gettext
