# SPDX-FileCopyrightText: Copyright (c) 2026 Infineon Technologies AG,
# SPDX-FileCopyrightText: or an affiliate of Infineon Technologies AG. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0

# PSE84 MCUboot XIP-encryption signing wrapper for chain-loaded slot apps.
#
# The stock cmake/mcuboot.cmake flow signs images chain-loaded by MCUboot
# (e.g. a standalone Secure CM33 app or a CM55 app). This wrapper is installed
# as the SIGNING_SCRIPT by pse84_signing.cmake when
# CONFIG_PSE84_MCUBOOT_XIP_ENCRYPTION is set. It derives the imgtool
# --encrypt-xip / --xip-base-address arguments from the build's slot0
# partition and appends them to CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS before
# running the stock flow, so the image is encrypted (AES-128-CTR) and then
# signed over the ciphertext.
#
# The TF-M (Non-Secure) build reuses this wrapper from pse84_tfm_signing.cmake
# to sign/encrypt the NSPE, then adds its SPE-merge steps on top.

include(${CMAKE_CURRENT_LIST_DIR}/pse84_metadata.cmake)

pse84_xip_encrypt_args(slot0_partition pse84_xip_args)
if(pse84_xip_args)
  list(JOIN pse84_xip_args " " pse84_xip_args_str)
  if("${CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS}" STREQUAL "")
    set(CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS "${pse84_xip_args_str}")
  else()
    set(CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS
        "${CONFIG_MCUBOOT_EXTRA_IMGTOOL_ARGS} ${pse84_xip_args_str}")
  endif()
endif()

include(${ZEPHYR_BASE}/cmake/mcuboot.cmake)
