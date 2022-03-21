#The patch is reverted to enable gles 3.0 (disabled by poky/meta layer)
SRC_URI_remove = "file://0002-hardware-gloat.patch"

PACKAGECONFIG[gallium] = ""
EXTRA_OECONF +=  "${@bb.utils.contains("MACHINE_FEATURES", "gsx", \
    "","--with-gallium-drivers='virgl swrast'", d)}"
