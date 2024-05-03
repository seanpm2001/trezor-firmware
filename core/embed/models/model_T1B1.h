#ifndef MODELS_MODEL_T1B1_H_
#define MODELS_MODEL_T1B1_H_

#define MODEL_NAME "1"
#define MODEL_FULL_NAME "Trezor Model One"
#define MODEL_INTERNAL_NAME "T1B1"
#define MODEL_INTERNAL_NAME_TOKEN T1B1
#define MODEL_INTERNAL_NAME_QSTR MP_QSTR_T1B1
#define MODEL_USB_MANUFACTURER "SatoshiLabs"
#define MODEL_USB_PRODUCT "TREZOR"

#define IMAGE_CHUNK_SIZE (64 * 1024)
#define IMAGE_HASH_SHA256

// SHARED WITH MAKEFILE
#define FLASH_START 0x08000000
#define BOOTLOADER_START 0x08000000
#define FIRMWARE_START 0x08010000
#define NORCOW_SECTOR_SIZE (1 * 64 * 1024)        // 64 kB
#define BOOTLOADER_IMAGE_MAXSIZE (1 * 32 * 1024)  // 32 kB
#define FIRMWARE_IMAGE_MAXSIZE (15 * 64 * 1024)   // 960 kB

#define BOOTLOADER_SECTOR_START 0
#define BOOTLOADER_SECTOR_END 2
#define FIRMWARE_SECTOR_START 4
#define FIRMWARE_SECTOR_END 11
#define STORAGE_1_SECTOR_START 2
#define STORAGE_1_SECTOR_END 2
#define STORAGE_2_SECTOR_START 3
#define STORAGE_2_SECTOR_END 3

#endif
