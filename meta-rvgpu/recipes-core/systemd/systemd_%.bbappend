FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}:"

SRC_URI_append = " \
    file://75-virtio-seat.rules \
    file://76-uinput-seat.rules \
"
