/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 Infineon Technologies AG,
 * SPDX-FileCopyrightText: or an affiliate of Infineon Technologies AG. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * PSE84 MCUboot XIP-encryption boot hook.
 *
 * Built only into the MCUboot image when CONFIG_BOOT_ENCRYPT_IMAGE_XIP is set.
 * MCUboot validates each image's ciphertext, unwraps its per-image AES-128 key
 * (ECIES-P256) and keeps the key/IV in the XIP-encryption library. This hook
 * runs after boot_go() and right before the jump; it programs the SMIF
 * on-the-fly AES-CTR crypto engine with that key material so the CPU fetches
 * plaintext from external flash.
 *
 * The SMIF derives the AES-CTR counter from the XIP fetch address, so only the
 * 128-bit key and the 96-bit nonce (the first 12 bytes of br_xip_iv) are
 * programmed here.
 */

#include <stdint.h>

#include <zephyr/devicetree.h>

#include "soc.h"
#include <cy_sysint.h>
#include <system_edge.h>
#include <cy_pdl.h>

#include <bootutil/bootutil.h>
#include <bootutil/boot_hooks.h>
#include <bootutil/image.h>
#include <flash_map_backend/flash_map_backend.h>

#if defined(CONFIG_BOOT_ENCRYPT_IMAGE_XIP)

/*
 * SMIF instance that memory-maps the external flash, taken from the QSPI flash
 * controller's devicetree register address. MCUboot runs secure, so force the
 * secure alias (bit 28, SECURE_ALIAS_OFFSET from the PDL) as the flash driver
 * does; this matches the SMIF0_CORE secure view the bootloader executes from.
 */
#define PSE84_XIP_SMIF_BASE                                                    \
	((SMIF_Type *)(DT_REG_ADDR(DT_NODELABEL(flash_controller)) |            \
		       SECURE_ALIAS_OFFSET))

/*
 * Slave select of the external flash. The kit_pse84_eval SOM wires the
 * S25FS128S on SMIF0 slave slot 1 (see IFX_SMIF_0_MEMORY_CONFIG). Hardcoded
 * until the QSPI flash chip-select lands in the devicetree binding.
 */
#define PSE84_XIP_SMIF_SLAVE CY_SMIF_SLAVE_SELECT_1

/*
 * Per-image external-flash XIP crypto regions. Each CM33/CM55 image runs from
 * its own slot; the SMIF decrypts fetches that fall in a key region. Each
 * region's size is the largest power of two that aligns its slot's base
 * (base & -base): that is the biggest region the SMIF can anchor at a base with
 * that alignment, it needs no base flooring, and CRYPTO_MASK stays a clean
 * contiguous bitmask (a non-power-of-2 size leaves holes in the mask). An image
 * must fit within its region, i.e. within its base's natural alignment: 1 MB
 * for m33s_xip @0x100000, 256 KB for m33_xip @0x340000, 512 KB for m55_xip
 * @0x580000. The BUILD_ASSERTs below pin the non-overlap to the devicetree, so
 * a slot-map change that breaks it fails the build.
 *
 * The SMIF match ignores the secure/non-secure top nibble, so all regions use
 * the non-secure SBUS base and still cover the secure image's 0x70... fetches.
 * The SMIF forms the AES-CTR counter from the SBUS fetch address and imgtool
 * anchors each image's ciphertext at its SBUS slot address (see
 * pse84_xip_encrypt_args), so INPUT0 == region base yields counter == fetch
 * address.
 *
 * Region index tracks the MCUboot image index: region 0 -> image 0 (m33s_xip),
 * region 1 -> image 1 (m33_xip), region 2 -> image 2 (m55_xip, CM55). A region
 * whose image has no stored key (fewer images than regions) is skipped at run
 * time. CRYPTO_MASK is a bitmask: A matches when
 * (A[31:8] & MASK[31:8]) == ADDR[31:8].
 */
/* Physical offset within the flash device: DT_REG_ADDR is the absolute address
 * in the slot's bus alias (CBUS-S 0x18.., CBUS-NS 0x08.., SBUS 0x60..), so mask
 * it down to the XIP window to get the offset the crypto engine matches on. */
#define PSE84_XIP_SLOT_OFFSET(node)                                            \
	(DT_REG_ADDR(DT_NODELABEL(node)) & (CY_XIP_PORT0_SIZE - 1u))
#define PSE84_XIP_SLOT_SBUS(node)                                              \
	(CY_XIP_PORT0_NS_SBUS_BASE + PSE84_XIP_SLOT_OFFSET(node))
/* Largest power of 2 aligning the slot base, and the matching CRYPTO_MASK. */
#define PSE84_XIP_REGION_ALIGN(node)                                           \
	(PSE84_XIP_SLOT_OFFSET(node) & (~PSE84_XIP_SLOT_OFFSET(node) + 1u))
#define PSE84_XIP_REGION_MASK(node)                                            \
	(SMIF_DEVICE_MASK_MASK_Msk & ~(PSE84_XIP_REGION_ALIGN(node) - 1u))
#define PSE84_XIP_REGION0_BASE PSE84_XIP_SLOT_SBUS(m33s_xip)
#define PSE84_XIP_REGION1_BASE PSE84_XIP_SLOT_SBUS(m33_xip)
#define PSE84_XIP_REGION2_BASE PSE84_XIP_SLOT_SBUS(m55_xip)
#define PSE84_XIP_REGION0_MASK PSE84_XIP_REGION_MASK(m33s_xip)
#define PSE84_XIP_REGION1_MASK PSE84_XIP_REGION_MASK(m33_xip)
#define PSE84_XIP_REGION2_MASK PSE84_XIP_REGION_MASK(m55_xip)

/* Adjacent regions must not overlap for the active slot map. */
BUILD_ASSERT(PSE84_XIP_SLOT_OFFSET(m33s_xip) + PSE84_XIP_REGION_ALIGN(m33s_xip) <=
		     PSE84_XIP_SLOT_OFFSET(m33_xip),
	     "image 0 (m33s_xip) and image 1 (m33_xip) XIP crypto regions overlap");
BUILD_ASSERT(PSE84_XIP_SLOT_OFFSET(m33_xip) + PSE84_XIP_REGION_ALIGN(m33_xip) <=
		     PSE84_XIP_SLOT_OFFSET(m55_xip),
	     "image 1 (m33_xip) and image 2 (m55_xip) XIP crypto regions overlap");

/* Number of per-image XIP crypto regions programmed by the jump hook. */
#define PSE84_XIP_REGION_COUNT 3u

struct pse84_xip_region {
	uint32_t base;
	uint32_t key[4];
	uint32_t iv[4];
	bool valid;
};

/* Volatile word-wipe the compiler may not elide. */
static void pse84_secure_zero(volatile uint32_t *p, uint8_t words)
{
	for (uint8_t i = 0u; i < words; i++) {
		p[i] = 0u;
	}
}

fih_ret boot_image_jump_hook(struct boot_rsp *rsp)
{
	SMIF_Type *smif = PSE84_XIP_SMIF_BASE;
	static const uint32_t region_base[PSE84_XIP_REGION_COUNT] = {
		PSE84_XIP_REGION0_BASE,
		PSE84_XIP_REGION1_BASE,
		PSE84_XIP_REGION2_BASE,
	};

	static const uint32_t region_mask[PSE84_XIP_REGION_COUNT] = {
		PSE84_XIP_REGION0_MASK,
		PSE84_XIP_REGION1_MASK,
		PSE84_XIP_REGION2_MASK,
	};
	struct pse84_xip_region regs[PSE84_XIP_REGION_COUNT];

	/*
	 * Collect each image's key/IV. boot_xip_populate_rsp() copies them into
	 * a scratch boot_rsp; an image with no stored key leaves the
	 * zero-initialised key untouched and is skipped. The MCUboot loader
	 * keeps the keys until this hook returns, so every image's key is
	 * available here.
	 */
	for (uint8_t i = 0u; i < PSE84_XIP_REGION_COUNT; i++) {
		struct boot_rsp tmp = {0};

		boot_xip_populate_rsp((int)i, &tmp);
		regs[i].base = region_base[i];
		regs[i].valid = (tmp.br_xip_key[0] | tmp.br_xip_key[1] |
				 tmp.br_xip_key[2] | tmp.br_xip_key[3]) != 0u;
		for (uint8_t w = 0u; w < 4u; w++) {
			regs[i].key[w] = tmp.br_xip_key[w];
			regs[i].iv[w] = tmp.br_xip_iv[w];
		}
	}

	/*
	 * CRYPTO_ADDR/CRYPTO_MASK only latch while the SMIF is disabled, so
	 * program them here. A single Cy_SMIF_SetCryptoKeyRegion() cannot be used:
	 * it would also write CRYPTO_KEY/CRYPTO_INPUT in this disabled window, and
	 * CRYPTO_INPUT (counter/nonce) written while disabled is cleared on the
	 * re-enable below (verified on hardware).
	 */
	SMIF_CTL(smif) &= ~SMIF_CTL_ENABLED_Msk;
	for (uint8_t i = 0u; i < PSE84_XIP_REGION_COUNT; i++) {
		if (!regs[i].valid) {
			continue;
		}
		SMIF_CRYPTO_IDX_ADDR(smif, i) = regs[i].base;
		SMIF_CRYPTO_IDX_MASK(smif, i) = region_mask[i];
	}
	SMIF_CTL(smif) |= SMIF_CTL_ENABLED_Msk;

	/*
	 * CRYPTO_KEY and CRYPTO_INPUT (counter/nonce) only persist while the
	 * SMIF is enabled (a disable clears CRYPTO_INPUT), so program them after
	 * re-enabling. INPUT0 seeds the AES-CTR counter; the SMIF then derives
	 * the per-fetch counter from the SBUS fetch address, so INPUT0 == region
	 * base yields counter == fetch address (the imgtool anchor).
	 */
	for (uint8_t i = 0u; i < PSE84_XIP_REGION_COUNT; i++) {
		if (!regs[i].valid) {
			continue;
		}
		SMIF_CRYPTO_IDX_KEY0(smif, i) = regs[i].key[0];
		SMIF_CRYPTO_IDX_KEY1(smif, i) = regs[i].key[1];
		SMIF_CRYPTO_IDX_KEY2(smif, i) = regs[i].key[2];
		SMIF_CRYPTO_IDX_KEY3(smif, i) = regs[i].key[3];
		SMIF_CRYPTO_IDX_INPUT0(smif, i) = regs[i].base;
		SMIF_CRYPTO_IDX_INPUT1(smif, i) = regs[i].iv[0];
		SMIF_CRYPTO_IDX_INPUT2(smif, i) = regs[i].iv[1];
		SMIF_CRYPTO_IDX_INPUT3(smif, i) = regs[i].iv[2];
		SMIF_CRYPTO_IDX_SUBREGION(smif, i) = 0x00u;
	}

	(void)Cy_SMIF_SetCryptoEnable(smif, PSE84_XIP_SMIF_SLAVE);
	/* Invalidate so the next fetch is served decrypted through the engine. */
	(void)Cy_SMIF_CacheInvalidate(smif, CY_SMIF_CACHE_BOTH);

	/*
	 * The SMIF has latched the keys, so wipe every remaining plaintext copy
	 * before returning: the MCUboot library store, our local copies and the
	 * loader-populated boot response. This keeps key material from
	 * outliving the hook.
	 */
	xip_enc_clear_keys();
	for (uint8_t i = 0u; i < PSE84_XIP_REGION_COUNT; i++) {
		pse84_secure_zero(regs[i].key, 4u);
		pse84_secure_zero(regs[i].iv, 4u);
	}
	if (rsp != NULL) {
		pse84_secure_zero(rsp->br_xip_key, 4u);
		pse84_secure_zero(rsp->br_xip_iv, 4u);
	}

	FIH_RET(FIH_SUCCESS);
}

/*
 * Enabling CONFIG_BOOT_ENCRYPT_IMAGE_XIP selects BOOT_IMAGE_ACCESS_HOOKS, which
 * makes MCUboot call the whole image-access hook set. The XIP library overrides
 * only boot_image_check_hook(); provide pass-through defaults for the rest so
 * the loader follows its normal path. They are weak so a platform can override.
 */
__attribute__((weak))
int boot_read_image_header_hook(int img_index, int slot,
				struct image_header *img_head)
{
	(void)img_index;
	(void)slot;
	(void)img_head;
	return BOOT_HOOK_REGULAR;
}

__attribute__((weak))
int boot_perform_update_hook(int img_index, struct image_header *img_head,
			     const struct flash_area *area)
{
	(void)img_index;
	(void)img_head;
	(void)area;
	return BOOT_HOOK_REGULAR;
}

__attribute__((weak))
int boot_read_swap_state_primary_slot_hook(int image_index,
					   struct boot_swap_state *state)
{
	(void)image_index;
	(void)state;
	return BOOT_HOOK_REGULAR;
}

__attribute__((weak))
int boot_copy_region_post_hook(int img_index, const struct flash_area *area,
			       size_t size)
{
	(void)img_index;
	(void)area;
	(void)size;
	return 0;
}

#endif /* CONFIG_BOOT_ENCRYPT_IMAGE_XIP */
