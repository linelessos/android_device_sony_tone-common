#!/vendor/bin/sh

MSIM_DEVICES=(
    F8132 # XPerf
    F8332 # XZ
    G8232 # XZs
)
MSIM_DEVICE=0

for device in "${MSIM_DEVICES[@]}"; do
    if grep -q "Model: ${device}" /dev/block/bootdevice/by-name/LTALabel; then
        MSIM_DEVICE=1
        break
    fi
done

if [[ "${MSIM_DEVICE}" -eq 1 ]]; then
    setprop persist.vendor.radio.multisim.config dsds
else
    setprop persist.vendor.radio.multisim.config ss
fi
