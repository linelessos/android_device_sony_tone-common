#!/sbin/sh
#
# Copyright (C) 2012 The Android Open Source Project
# Copyright (C) 2016 The OmniROM Project
# Copyright (C) 2018 Choose-A project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

# check mounts
check_mount() {
    local MOUNT_POINT=$(readlink "${1}");
    if ! test -n "${MOUNT_POINT}" ; then
        # readlink does not work on older recoveries for some reason
        # doesn't matter since the path is already correct in that case
        echo "Using non-readlink mount point ${1}";
        MOUNT_POINT="${1}";
    fi
    if ! grep -q "${MOUNT_POINT}" /proc/mounts ; then
        mkdir -p "${MOUNT_POINT}";
        if ! mount -t "${3}" "${2}" "${MOUNT_POINT}" ; then
             echo "Cannot mount ${1} (${MOUNT_POINT}).";
             exit 1;
        fi
    fi
}

# check partitions
check_mount /lta-label /dev/block/bootdevice/by-name/LTALabel ext4;
check_mount /oem /dev/block/bootdevice/by-name/oem ext4;

setvariant=$(\
    cat /oem/build.prop | \
    grep ro.sony.variant | \
    sed s/.*=// \
);

# Detect the exact model from the LTALabel partition
# This looks something like:
# 1284-8432_5-elabel-D5303-row.html
variant=$(\
    ls /lta-label/*.html | \
    sed s/.*-elabel-// | \
    sed s/-.*.html// | \
    tr -d '\n\r' | \
    tr '[a-z]' '[A-Z]' \
);

insertvariant() {
if [[ "$variant" == "F8331" ]]
then
    $(echo "ro.sony.variant=${variant}" >> /oem/build.prop);
    $(echo "ro.telephony.default_network=9,1" >> /oem/build.prop);
    $(echo "ro.product.model=XPeria XZ" >> /oem/build.prop);
    $(echo "ro.semc.product.model=F8331" >> /oem/build.prop);
    $(echo "ro.semc.version.sw=1302-9162" >> /oem/build.prop);
    $(echo "ro.semc.ms_type_id=PM-0980-BV" >> /oem/build.prop);
    $(echo "ro.semc.product.name=Xperia XZ" >> /oem/build.prop);
    $(echo "ro.semc.product.device=F83" >> /oem/build.prop);
    $(echo "ro.semc.version.sw_variant=GLOBALDS-LTE3D" >> /oem/build.prop);
    $(echo "ro.build.description=kagura-user 8.0.0 OPR1.170623.026 1 dev-keys" >> /oem/build.prop);
    $(echo "ro.bootimage.build.fingerprint=Sony/kagura/kagura:8.0.0/OPR1.170623.026/1:user/dev-keys" >> /oem/build.prop);
elif [[ "$variant" == "F8332" ]]
then
    $(echo "ro.sony.variant=${variant}" >> /oem/build.prop);
    $(echo "persist.multisim.config=dsds" >> /oem/build.prop);
    $(echo "persist.radio.multisim.config=dsds" >> /oem/build.prop);
    $(echo "ro.telephony.ril.config=simactivation" >> /oem/build.prop);
    $(echo "ro.telephony.default_network=9,1" >> /oem/build.prop);
    $(echo "ro.product.model=XPeria XZ DualSim" >> /oem/build.prop);
    $(echo "ro.semc.product.model=F8332" >> /oem/build.prop);
    $(echo "ro.semc.version.sw=1302-9162" >> /oem/build.prop);
    $(echo "ro.semc.ms_type_id=PM-0980-BV" >> /oem/build.prop);
    $(echo "ro.semc.product.name=Xperia XZ Dualsim" >> /oem/build.prop);
    $(echo "ro.semc.product.device=F83" >> /oem/build.prop);
    $(echo "ro.semc.version.sw_variant=GLOBALDS-LTE3D" >> /oem/build.prop);
    $(echo "ro.build.description=kagura_dsds-user 8.0.0 OPR1.170623.026 1 dev-keys" >> /oem/build.prop);
    $(echo "ro.bootimage.build.fingerprint=Sony/kagura_dsds/kagura_dsds:8.0.0/OPR1.170623.026/1:user/dev-keys" >> /oem/build.prop);
elif [[ "$variant" == "F8131" ]]
then
    $(echo "ro.sony.variant=${variant}" >> /oem/build.prop);
    $(echo "ro.telephony.default_network=9,1" >> /oem/build.prop);
    $(echo "ro.product.model=XPeria XZ" >> /oem/build.prop);
    $(echo "ro.semc.product.model=F8131" >> /oem/build.prop);
    $(echo "ro.semc.version.sw=1304-1564" >> /oem/build.prop);
    $(echo "ro.semc.version.sw_variant=R1E" >> /oem/build.prop);
    $(echo "ro.build.description=dora-user 8.0.0 OPR1.170623.026 1 dev-keys" >> /oem/build.prop);
    $(echo "ro.bootimage.build.fingerprint=Sony/dora/dora:8.0.0/OPR1.170623.026/1:user/dev-keys" >> /oem/build.prop);
fi
}

# Set the variant as a prop
if [[ "$setvariant" == "$variant" ]]
then
    echo "Variant already set!";
else
    insertvariant;
    chmod 0644 /oem/build.prop;
fi
exit 0
