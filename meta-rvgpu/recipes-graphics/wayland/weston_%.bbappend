# Remove the RPATH variable, to be able to use LD_LIBRARY_PATH,
# to run render apps using /usr/lib/mesa-virtio
do_install_append() {
	chrpath --delete ${D}${libdir}/libweston-8/*.so
	chrpath --delete ${D}${libdir}/weston/*.so
	chrpath --delete ${D}${libdir}/*.so
}
