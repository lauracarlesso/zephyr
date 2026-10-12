<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Infineon Technologies AG,
SPDX-FileCopyrightText: or an affiliate of Infineon Technologies AG. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# PSE84 MCUboot XIP Encryption

On-the-fly (execute-in-place) encryption for PSE84 images stored in external
QSPI flash. Each image stays encrypted at rest; the SMIF block decrypts
instructions transparently as the CPU fetches them. Every image is encrypted
with its own independent AES-128 key, so the images are not cryptographically
linked.

- Boot hook: [`pse84_mcuboot_xip.c`](pse84_mcuboot_xip.c)
- Signing helpers: [`pse84_metadata.cmake`](pse84_metadata.cmake),
  [`pse84_xip_signing.cmake`](pse84_xip_signing.cmake),
  [`pse84_tfm_signing.cmake`](pse84_tfm_signing.cmake)
- MCUboot XIP library: `bootloader/mcuboot/boot/bootutil/src/xip_enc/`

## How it works

1. **Sign time (`imgtool`).** For each image, imgtool generates a random
   AES-128 key, encrypts the payload with AES-CTR whose counter is anchored at
   the image's SBUS execution address, wraps the key with ECIES-P256 to the
   device encryption public key, and signs over the **ciphertext**. The image
   header and TLVs stay in plaintext.
2. **Boot time (MCUboot).** For every image it manages, MCUboot hashes the
   ciphertext, verifies the signature, ECIES-unwraps the per-image AES key, and
   stores it. Right before jumping, the SoC `boot_image_jump_hook` programs one
   SMIF crypto region per image (key + nonce + region address), enables the
   crypto engine, invalidates the cache, and wipes the plaintext keys from RAM.
3. **Run time (SMIF).** Each fetch into a crypto region is decrypted on the
   fly. The AES-CTR counter is the SBUS fetch address, so the keystream matches
   what imgtool used.

```
imgtool: random AES key --AES-CTR--> ciphertext  (+ ECIES-wrapped key TLV, signature)
MCUboot: verify ciphertext -> ECIES-unwrap key -> jump hook programs SMIF region
SMIF:    fetch @ SBUS addr -> AES-CTR(key, counter=addr) -> plaintext instruction
```

## Keys

| Key | Role | Where the private half lives |
|-----|------|------------------------------|
| `root-ec-p256.pem` | image signing (authenticity) | with the signer; public half compiled into MCUboot |
| `enc-ec256-pub.pem` / `enc-ec256-priv.pem` | ECIES key wrapping (confidentiality) | private half compiled into MCUboot |
| per-image AES-128 | payload encryption | generated per build, never stored in plaintext |

The sample keys live in `bootloader/mcuboot/`. **Replace them before shipping.**

## Requirements and limitations

- **Signature is mandatory.** `CONFIG_BOOT_ENCRYPT_IMAGE_XIP` selects ECDSA-P256
  verification; an unsigned encrypted image is rejected.
- **The bootloader must manage every encrypted image.** It only unwraps a key
  for an image it validates, so `CONFIG_UPDATEABLE_IMAGE_NUMBER` must equal the
  number of images (1, 2 or 3). With a lower value the extra images get no
  crypto region and fetch as ciphertext.
- **Maximum three images.** `XIP_ENC_MAX_IMAGES = 3`, matching the SMIF's usable
  crypto key regions. The jump hook programs regions 0/1/2 for `m33s_xip`
  (SPE/secure), `m33_xip` (NSPE), `m55_xip` (CM55); a region whose image has no
  stored key is skipped.
- **One power-of-2 crypto region per image, sized from the devicetree.** The
  jump hook sizes each region to the largest power of two that aligns its slot's
  base (`base & -base`), so `CRYPTO_MASK` is a clean contiguous bitmask and no
  base flooring is needed. `CRYPTO_MASK` is a hardware bitmask, not a size: an
  address matches when `(A[31:8] & MASK[31:8]) == ADDR[31:8]`, so a region is
  always a power-of-2 span. Two `BUILD_ASSERT`s pin the non-overlap to the
  devicetree. With the current slot map the regions are:

  | Image | Slot | Base alignment → region | Max image size |
  |-------|------|-------------------------|----------------|
  | SPE (image 0) | `m33s_xip` @ `0x100000` | 1 MB — `0x60100000`, mask `0xFFF00000` | 1 MB |
  | NSPE (image 1) | `m33_xip` @ `0x340000` | 256 KB — `0x60340000`, mask `0xFFFC0000` | 256 KB |
  | CM55 (image 2) | `m55_xip` @ `0x580000` | 512 KB — `0x60580000`, mask `0xFFF80000` | 512 KB |

  Each region size is capped by its slot base's natural alignment (so `m33_xip`
  at `0x340000`, being only 256 KB-aligned, gets a 256 KB region). That is ample
  for the current ~40 KB images; to grow a region, align the slot base to a
  larger power of two (see "Crypto region sizing and memory layout" below).
- **The region covers the slot only when the base is naturally aligned.** The
  derived region spans `base_alignment` bytes from the base, so it covers the
  whole slot only when `base_alignment >= slot_size`. `CRYPTO_MASK` being a
  bitmask means a non-power-of-2 size (e.g. passing the raw slot size) produces a
  **non-contiguous** region with holes — do not do that; always use a power of
  two.
- **The NSPE slot address is shared with TF-M.** The TF-M Secure image enters
  the Non-Secure image at the address in the TF-M generated memory layout
  (`CYMEM_CM33_0_m33_nvm`), `0x340000` today. Relocating `m33_xip` in the Zephyr
  devicetree alone breaks the boot (the SPE jumps to the old address) unless the
  TF-M entry is also moved — either by regenerating the TF-M memory layout or by
  overriding the entry address in code. The CM55 layout must move with it too.
- **Counter anchoring differs by bus.** `imgtool --xip-base-address` is the SBUS
  execution address. For CBUS-resident slots (`flash0_s` secure `0x18…`, `flash0`
  non-secure `0x08…`) the signing helper adds the fixed `+0x58000000` CBUS→SBUS
  delta. The CM55 slot is already SBUS (`flash0_sahb`, `0x60…`) and is used
  as-is. Secure images anchor at `0x70…`, non-secure at `0x60…`; the SMIF region
  match ignores the secure/non-secure top nibble, so a `0x60` region also covers
  `0x70` fetches of the same offset.
- **Keys are short-lived in RAM.** The jump hook wipes the MCUboot key store,
  its local copies and the boot response immediately after programming the SMIF.
- **No swap-time re-encryption is needed.** Because the ciphertext is anchored
  at the primary address and validated as ciphertext, `swap-using-move` relocates
  the encrypted bytes verbatim and they still decrypt once in the primary slot
  (verified on hardware). There is no `boot_encrypt_xip` in this flow.
- **`SW6` (`BOOT SW`) must be OFF** so the ROM extended boot enters MCUboot in
  RRAM rather than jumping straight to external flash.

## Crypto region sizing and memory layout

A crypto region covers a whole slot only when the slot is **naturally aligned**:
a power-of-2 size based at an address that is a multiple of that size. The jump
hook derives each region as `base & -base` (the largest power of two that aligns
the slot base), so:

- the region fully covers the slot when `base_alignment >= slot_size`;
- if the base is under-aligned for the slot size, the region covers only the
  first `base_alignment` bytes and fetches past it fault.

Rule of thumb: **put each slot on an address aligned to its size.**

The current slots are not naturally aligned for their full size (`m33_xip` at
`0x340000` is only 256 KB-aligned, `m55_xip` at `0x580000` is 512 KB-aligned), so
each image is limited to its base's alignment. That is ample for the current
~40 KB images but caps growth.

### Recommended naturally-aligned 2 MB layout

Placing the slots on power-of-2 boundaries gives each image a region that covers
its whole slot:

| Slot | Base | Size | Region | Covers slot |
|------|------|------|--------|-------------|
| `storage_partition` | `0x000000` | 1 MB | — (plaintext) | — |
| SPE `m33s_xip` | `0x100000` | 1 MB | `0x100000–0x200000` (1 MB) | yes |
| NSPE `m33_xip` | `0x200000` | 2 MB | `0x200000–0x400000` (2 MB) | yes |
| CM55 `m55_xip` | `0x400000` | ≤ 4 MB | `0x400000–0x800000` (4 MB) | yes |

Each base is aligned to its size, so `base & -base` yields a region that spans
the entire slot, and the `BUILD_ASSERT`s confirm the regions do not overlap. No
hook change is needed — the region sizes follow the devicetree automatically.

Caveats for this redesign:

- **Secondary (upgrade) slots double the footprint.** Swap-using-move needs an
  equal-sized secondary per image, so the 2 MB layout uses
  `1+1 + 2+2 + 2+2 = 10 MB` of the 16 MB device.
- **Moving NSPE/CM55 is not a Zephyr-only change.** The TF-M Secure image enters
  the NSPE at the TF-M generated memory-layout address, and the CM55 build has
  its own layout; both must move with the Zephyr slots (or the entry address must
  be overridden in code), or the SPE will jump to the old NSPE location.
  The updates needed on the TF-M side are
  1. Update cymem_cm33_0.h file in  with the new offset/address/size of m33_nvm defines and
  correct the m33s_nvm one.
  2. Update the addresses/sizes of M33_M55_mpc_regions for smif entries
  3. Update M33s_mpc_regions with the new size of the smif entries
  4. Update smif_0_mpc_0_srf_protection_range_s with the new address/size of the non secure area
  and the new offset and size of the secure area.

## Enabling it

Application side (opt-in), e.g.
[`kit_pse84_eval_xip_enc.conf`](../../../../boards/infineon/kit_pse84_eval/kit_pse84_eval_xip_enc.conf):

```ini
CONFIG_PSE84_MCUBOOT_XIP_ENCRYPTION=y
CONFIG_PSE84_MCUBOOT_XIP_ENC_KEY_FILE="<path>/enc-ec256-pub.pem"
```

Bootloader side (opt-in), e.g.
`bootloader/mcuboot/boot/zephyr/boards/kit_pse84_eval_pse846gps2dbzc4a_m33_xip_enc.conf`:

```ini
CONFIG_BOOT_ENCRYPT_IMAGE_XIP=y
CONFIG_BOOT_IMAGE_JUMP_HOOKS=y
CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y
CONFIG_BOOT_SIGNATURE_KEY_FILE="root-ec-p256.pem"
CONFIG_BOOT_ENCRYPTION_KEY_FILE="enc-ec256-priv.pem"
```

## Build and flash

Set `UPDATEABLE_IMAGE_NUMBER` on the bootloader to the image count. The variables
below assume:

```bash
Z=$ZEPHYR_BASE
M=<path>/bootloader/mcuboot
```

### Bootloader

```bash
west build -b kit_pse84_eval/pse846gps2dbzc4a/m33 \
    $M/boot/zephyr -d build_mcuboot -p always -- \
    -DCONFIG_UPDATEABLE_IMAGE_NUMBER=<1|2|3> \
    -DEXTRA_CONF_FILE=boards/kit_pse84_eval_pse846gps2dbzc4a_m33_xip_enc.conf

west flash -d build_mcuboot
```

Always pristine-build the bootloader after changing its config; an incremental
build does not re-run Kconfig.

### Single secure CM33 app (image 0)

```bash
west build -b kit_pse84_eval/pse846gps2dbzc4a/m33 samples/hello_world \
    -d build_app -p always -- \
    -DEXTRA_CONF_FILE="$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_slot.conf;$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_xip_enc.conf" \
    -DCONFIG_MCUBOOT_SIGNATURE_KEY_FILE=\"$M/root-ec-p256.pem\" \
    -DCONFIG_PSE84_MCUBOOT_XIP_ENC_KEY_FILE=\"$M/enc-ec256-pub.pem\"

west flash -d build_app
```

### TF-M SPE + NSPE (images 0 and 1)

Building the `/ns` target builds TF-M as the SPE and the Zephyr app as the NSPE,
signs/encrypts both, and produces `tfm_merged.hex`.

```bash
west build -b kit_pse84_eval/pse846gps2dbzc4a/m33/ns samples/hello_world \
    -d build_tfm_ns -p always -- \
    -DEXTRA_CONF_FILE="$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_slot.conf;$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_xip_enc.conf" \
    -DCONFIG_MCUBOOT_SIGNATURE_KEY_FILE=\"$M/root-ec-p256.pem\" \
    -DCONFIG_PSE84_MCUBOOT_XIP_ENC_KEY_FILE=\"$M/enc-ec256-pub.pem\"

west flash -d build_tfm_ns     # flashes tfm_merged.hex (SPE @ 0x70100000, NSPE @ 0x60340000)
```

### Adding the CM55 app (image 2)

The CM55 build consumes the CM33-NS PSA headers, so build CM33-NS first and point
the CM55 build at it with `PSE84_CM33_BUILD_DIR`. Both set
`CONFIG_PSOC_EDGE_M55_SRF_SUPPORT=y`; the bootloader uses
`-DCONFIG_UPDATEABLE_IMAGE_NUMBER=3`.

```bash
# CM33-NS (SPE + NSPE), SRF enabled
west build -b kit_pse84_eval/pse846gps2dbzc4a/m33/ns samples/hello_world \
    -d build_mc33 -p always -- -DCONFIG_PSOC_EDGE_M55_SRF_SUPPORT=y \
    -DEXTRA_CONF_FILE="$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_slot.conf;$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_xip_enc.conf" \
    -DCONFIG_MCUBOOT_SIGNATURE_KEY_FILE=\"$M/root-ec-p256.pem\" \
    -DCONFIG_PSE84_MCUBOOT_XIP_ENC_KEY_FILE=\"$M/enc-ec256-pub.pem\"

# CM55 app (image 2), SRF enabled, pointed at the CM33-NS build
west build -b kit_pse84_eval/pse846gps2dbzc4a/m55 samples/basic/blinky \
    -d build_mc55 -p always -- -DCONFIG_PSOC_EDGE_M55_SRF_SUPPORT=y \
    -DPSE84_CM33_BUILD_DIR=build_mc33 \
    -DEXTRA_CONF_FILE="$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_slot.conf;$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_xip_enc.conf" \
    -DCONFIG_MCUBOOT_SIGNATURE_KEY_FILE=\"$M/root-ec-p256.pem\" \
    -DCONFIG_PSE84_MCUBOOT_XIP_ENC_KEY_FILE=\"$M/enc-ec256-pub.pem\"

west flash -d build_mcuboot    # 3-image bootloader
west flash -d build_mc55       # CM55 @ 0x60580000
west flash -d build_mc33       # SPE @ 0x70100000 + NSPE @ 0x60340000
```

## OTA upgrade (swap-using-move)

The board uses `swap-using-move`: the application build places the signed,
encrypted image in the **primary** slot. To upgrade, stage a second image in the
**secondary** slot with a swap trailer, and MCUboot swaps it in on the next reset.

The critical rule for an encrypted upgrade: **anchor the encryption at the
primary (execution) address but place the hex at the secondary slot address.**
The two `imgtool` addresses differ, because the image is staged in the secondary
slot but will execute from the primary after the swap.

Example for image 0 (secure CM33), primary `m33s_xip` @ `0x70100000`, secondary
`m33s_upgrade` @ `0x70700000`:

```bash
# Build the new version (bump the version so downgrade prevention accepts it).
west build -b kit_pse84_eval/pse846gps2dbzc4a/m33 samples/hello_world \
    -d build_app_v2 -p always -- \
    -DEXTRA_CONF_FILE="$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_slot.conf;$Z/boards/infineon/kit_pse84_eval/kit_pse84_eval_xip_enc.conf" \
    -DCONFIG_MCUBOOT_SIGNATURE_KEY_FILE=\"$M/root-ec-p256.pem\" \
    -DCONFIG_PSE84_MCUBOOT_XIP_ENC_KEY_FILE=\"$M/enc-ec256-pub.pem\" \
    -DCONFIG_MCUBOOT_IMGTOOL_SIGN_VERSION=\"1.0.1+0\"

# Re-sign the raw binary for the secondary slot: encrypt anchored at the PRIMARY
# address, place the hex at the SECONDARY address, add a swap trailer (--pad).
python $M/scripts/imgtool.py sign \
    --version 1.0.1+0 --header-size 0x400 --slot-size 0x240000 --align 16 \
    --key $M/root-ec-p256.pem \
    --encrypt-xip $M/enc-ec256-pub.pem --xip-base-address 0x70100000 \
    --pad --hex-addr 0x70700000 \
    build_app_v2/zephyr/zephyr.bin build_app_v2/zephyr/upgrade_sec.hex

# Flash only the secondary slot; the primary image is left untouched.
west flash -d build_app_v2 --no-rebuild \
    --hex-file build_app_v2/zephyr/upgrade_sec.hex
```

On the next reset MCUboot logs `Swap type: test`, runs the swap-using-move
algorithm, and boots the new version.

- `--pad` requests a **test** swap: the upgrade runs once and MCUboot **reverts**
  on the following reset unless the application confirms it (via
  `boot_write_img_confirmed()` or an image signed with `--pad --confirm`).
- `--pad --confirm` makes the upgrade permanent immediately.
- `--header-size` must match `CONFIG_ROM_START_OFFSET` (`0x400`); `--align` and
  `--slot-size` must match the slot geometry. Do not pass `--pad-header` for a
  Zephyr image (it already reserves the header via `CONFIG_ROM_START_OFFSET`);
  the TF-M SPE binary does need `--pad-header`.

For a multi-image setup each image has its own primary/secondary pair
(`m33s_xip`/`m33s_upgrade`, `m33_xip`/`m33_upgrade`, `m55_xip`/`m55_upgrade`), so
an upgrade of one image is staged independently in that image's secondary slot.
Images can be upgraded together: stage each secondary, then reset once and
MCUboot swaps them all.

Example staging both TF-M images (SPE image 0 + NSPE image 1) from a v1.0.1
build. The SPE is a TF-M binary and needs `--pad-header` as well as `--pad`; the
Zephyr NSPE needs only `--pad`:

```bash
# SPE (image 0): secure, primary 0x70100000 -> secondary m33s_upgrade 0x70700000
python $M/scripts/imgtool.py sign \
    --version 1.0.1+0 --header-size 0x400 --pad-header --slot-size 0x240000 --align 16 \
    --key $M/root-ec-p256.pem \
    --encrypt-xip $M/enc-ec256-pub.pem --xip-base-address 0x70100000 \
    --pad --hex-addr 0x70700000 \
    build_tfm_v2/tfm/bin/tfm_s.hex build_tfm_v2/zephyr/spe_upgrade_sec.hex

# NSPE (image 1): non-secure, primary 0x60340000 -> secondary m33_upgrade 0x60940000
python $M/scripts/imgtool.py sign \
    --version 1.0.1+0 --header-size 0x400 --slot-size 0x1c0000 --align 16 \
    --key $M/root-ec-p256.pem \
    --encrypt-xip $M/enc-ec256-pub.pem --xip-base-address 0x60340000 \
    --pad --hex-addr 0x60940000 \
    build_tfm_v2/zephyr/zephyr.bin build_tfm_v2/zephyr/nspe_upgrade_sec.hex

west flash -d build_tfm_v2 --no-rebuild --hex-file build_tfm_v2/zephyr/spe_upgrade_sec.hex
west flash -d build_tfm_v2 --no-rebuild --hex-file build_tfm_v2/zephyr/nspe_upgrade_sec.hex
```

On reset MCUboot swaps both (`Image index: 0` and `Image index: 1`, each
`Swap type: test`) and boots the upgraded, decrypted images.
