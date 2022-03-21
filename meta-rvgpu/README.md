Introduction
------------

This repository contains Panasonic Remote Virtio GPU Device (RVGPU).

This repository contains Panasonic additions for RVGPU support to the Renesas
OpenEmbedded/Yocto BSP layer for Renesas Electronics's SoCs, located at:

http://github.com/renesas-rcar/meta-renesas.git

# Building with RCAR Yocto v5.1.0

## Adding meta-rvgpu layer

The meta-rvgpu layer must be copied into the yocto work directory.

Add layer to yocto build:

cd ~/h3ulcb/build

bitbake-layers add-layer ../meta-rvgpu

### Build BSP for the Rcar H3 board

Refer to https://elinux.org/R-Car/Boards/Yocto-Gen3/v5.1.0 for build instruction

# Building with AGL

##  Adding meta-rvgpu layer

The meta-rvgpu layer must be copied into the AGL yocto work directory.

Add layer to yocto build:

cd ~/AGL/build

bitbake-layers add-layer ../meta-rvgpu

### Enable Waltham remote display feature

```shell
echo -e "AGL_FEATURES:append = \" waltham-remoting\"\n" >> build/conf/local.conf
```

### Build AGL for the Rcar H3 board

Refer to https://docs.automotivelinux.org/en/master/#0_Getting_Started/2_Building_AGL_Image/5_3_RCar_Gen_3
for build instruction

#### HowTo launch Waltham remote rendering

Connect two Rcar H3 boards via ethernet.

A display should be connected to the target board.

##### Launch Waltham on the target

Move waltham-receiver to /usr/bin

```shell
mv /var/local/lib/afm/applications/waltham-receiver/bin/waltham-receiver /usr/bin
```

Launch waltham-receiver:

```shell
waltham-receiver -p 10000
```

##### Launch Waltham on the source

Adjust the waltham-transmitter configuration and setup glmark2 to run remotely.

Edit the /etc/xdg/weston/weston.ini file as following:

```
[transmitter-output]
name=transmitter-1
mode=800x600@60
host=<target-ip-address>
port=10000
agl-shell-app-id=com.github.glmark2.glmark2
```

Waltham-transmitter component requires a hardcoded agl-compositor.ini file.

Create a link to weston.ini file.

```shell
ln -s /etc/xdg/weston/weston.ini /etc/xdg/weston/agl-compositor.ini
```

Reboot the board and launch glmark2-es2-wayland.

It should be displayed on the target board display.

Dual EGL/GLES support(both Power VR and mesa are packaged in the weston image)
-----------------------------------------------------------------------------
To run application using mesa
export LD_LIBRARY_PATH=/usr/lib/mesa-virtio
