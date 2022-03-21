# Remote virtio GPU user packages only supports 64bit.
REMOTE_VIRTIO_GPU_USER_PKGS = ""
REMOTE_VIRTIO_GPU_USER_PKGS_aarch64-poky-linux = " \
    remote-virtio-gpu \
"

IMAGE_INSTALL_append = " \
    ${REMOTE_VIRTIO_GPU_USER_PKGS} \
"

# Mesa built with virtio support
IMAGE_INSTALL_append = " \
    mesa-virtio \
"

# OpenPGM library
IMAGE_INSTALL_append = " \
    libpgm \
"

# ZeroMQ library
IMAGE_INSTALL_append = " \
    zeromq \
"

# Benchmark tools
IMAGE_INSTALL_append = " \
    glmark2 \
"
