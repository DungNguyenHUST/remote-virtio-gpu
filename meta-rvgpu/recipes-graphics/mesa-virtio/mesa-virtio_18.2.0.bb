SUMMARY = "Mesa library"
SECTION = "graphics"

LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://docs/license.html;md5=725f991a1cc322aa7a0cd3a2016621c4"

DEPENDS = "expat makedepend-native flex-native bison-native libxml2-native zlib chrpath-replacement-native"
DEPENDS_append = " libdrm wayland wayland-native wayland-protocols python3"

SRC_URI = "https://mesa.freedesktop.org/archive/mesa-${PV}.tar.xz \
           file://0001-glBufferData-Update-resource-backing-memory.patch \
           file://0001-Use-wayland-scanner-in-the-path.patch \
          "

SRC_URI[md5sum] = "88e1a7f31f259cec69bb76b3cb10c956"
SRC_URI[sha256sum] = "22452bdffff8e11bf4284278155a9f77cb28d6d73a12c507f1490732d0d9ddce"

S = "${WORKDIR}/mesa-${PV}"

inherit autotools pkgconfig gettext python3native

EXTRA_OEMAKE += "WAYLAND_PROTOCOLS_DATADIR=${STAGING_DATADIR}/wayland-protocols"

EXTRA_OECONF = " \
	     --prefix=/usr/lib/mesa-virtio \
	     --exec_prefix=/usr/lib/mesa-virtio \
	     --libdir=/usr/lib/mesa-virtio \
	     --includedir=/usr/include/mesa-virtio \
	     --sysconfdir=/etc/mesa-virtio \
	     --datadir=/usr/share/mesa-virtio \
	     "

EXTRA_OECONF_append = " \
		    --with-dri-drivers=swrast \
		    --with-gallium-drivers=swrast,virgl \
		    --with-platforms=drm,wayland \
		    --disable-glx \
		    --disable-dri3 \
			PYTHON2=python3 \
		    "

INSANE_SKIP_${PN} = "dev-so"

FILES_${PN} = " \
	    /usr/lib/mesa-virtio/* \
	    /etc/mesa-virtio/drirc \
	    /usr/share/mesa-virtio/* \
	    "
