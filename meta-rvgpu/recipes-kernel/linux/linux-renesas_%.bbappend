DESCRIPTION = "Enable linux virtio-gpu driver and VSYNC support \
"

FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}/:"

LINUX_MAJOR = "${@(d.getVar('LINUX_VERSION') or "x.y").split('.')[0]}"
LINUX_MINOR = "${@(d.getVar('LINUX_VERSION') or "x.y").split('.')[1]}"

SRC_URI_append = " \
    file://virtio-gpu.cfg \
    file://uinput.cfg \
    file://0001-drm-virtio-Add-VSYNC-support-linux-${LINUX_MAJOR}-${LINUX_MINOR}.patch \
"
