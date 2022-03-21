require include/rvgpu-common.inc

SUMMARY = "remote-virtio-gpu device"
SECTION = "graphics"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

SRC_URI_BASE = "${RVGPU_SRC_URI_BASE}"
SRCREV = "${AUTOREV}"
BRANCH = "master"
SRC_URI = "git://git@${SRC_URI_BASE}/proj-e0672/remote-virtio-gpu.git;protocol=ssh;branch=${BRANCH} \
		   file://virgl.capset \
		   "

S = "${WORKDIR}/git"

includedir = "${RENESAS_DATADIR}/include"
SSTATE_DUPWHITELIST += "${STAGING_INCDIR}"

# Build virtio kernel module without suffix
KERNEL_MODULE_PACKAGE_SUFFIX = ""

DRV_BUILD_DIR = "${WORKDIR}/build/src/rvgpu-driver-linux"
RVGPU_BUILD_DIR = "${WORKDIR}/build/src"

DEPENDS = "virglrenderer mesa wayland libepoxy libinput zeromq linux-renesas"

OECMAKE_GENERATOR = "Unix Makefiles"
EXTRA_OECMAKE += "-DCMAKE_BUILD_TYPE=Release -DVIRTIO_LO_DIR=${S}/src/rvgpu-driver-linux -DKERNELHEADERS_DIR=${KDIR}"

inherit cmake pkgconfig module

do_install () {
	# Create destination directries
	install -d ${D}/lib/modules/${KERNEL_VERSION}/extra/
	install -d ${D}/${includedir}/linux
	install -d ${KERNELSRC}/include
	install -d ${D}/${bindir}
	install -d ${D}/${libdir}
	install -d ${D}/${sysconfdir}

	# This file installed in SDK by kernel-devsrc pkg.
	install -m 644 ${DRV_BUILD_DIR}/Module.symvers ${KERNELSRC}/include/virtio_lo.symvers

	# Install kernel module
	install -m 644 ${DRV_BUILD_DIR}/virtio_lo.ko ${D}/lib/modules/${KERNEL_VERSION}/extra/

	# Install shared header file
	install -m 644 ${S}/src/rvgpu-driver-linux/include/uapi/linux/virtio_lo.h ${D}/${includedir}/linux/

	# Install rvgpu-proxy device
	install -m 755 ${RVGPU_BUILD_DIR}/rvgpu-proxy/rvgpu-proxy ${D}/${bindir}

	# Install rvgpu-renderer device
	install -m 755 ${RVGPU_BUILD_DIR}/rvgpu-renderer/rvgpu-renderer ${D}/${bindir}

	# Install rvgpu library
	install -m 755 ${RVGPU_BUILD_DIR}/librvgpu/librvgpu.so.1.0.0 ${D}/${libdir}
	cd ${D}/${libdir}
	ln -s librvgpu.so.1.0.0 librvgpu.so.1
	ln -s librvgpu.so.1 librvgpu.so

	# Install the virgl capabilities file
	install -m 0644 ${WORKDIR}/virgl.capset ${D}/${sysconfdir}
}

FILES_${PN} += " \
    /lib/modules/${KERNEL_VERSION}/extra/virtio_lo.ko \
    ${sysconfdir}/modules-load.d \
    ${sysconfdir}/*.capset \
    ${bindir}/rvgpu* \
	${libdir}/librvgpu* \
"

RPROVIDES_${PN} += "kernel-module-virtiolo kernel-module-virtio-lo"

# Autoload virtio lo driver
KERNEL_MODULE_AUTOLOAD_append = " virtio_lo"

FILES_SOLIBSDEV = ""
INSANE_SKIP_${PN} += "dev-so"
