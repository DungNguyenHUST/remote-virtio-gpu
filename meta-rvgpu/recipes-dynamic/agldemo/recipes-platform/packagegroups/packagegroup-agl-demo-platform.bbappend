RDEPENDS_${PN} += " \
	remote-virtio-gpu \
	mesa-virtio \
	libpgm \
	zeromq \
	glmark2 \
"

# Waltham packages for remote display support
RDEPENDS_${PN} += " \
	waltham \
	waltham-transmitter-plugin \
	waltham-receiver \
"
