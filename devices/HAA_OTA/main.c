/*
 * Espy House OTA Update
 *
 * Copyright 2020 Expert Ninja
 *
 */

/*
 * Based on Home Accessory Architect (HAA) by José Antonio Jiménez Campos (@RavenSystem), licensed under Apache License 2.0.
 * https://github.com/RavenSystem/esp-homekit-devices
 *
 * Based on Life-Cycle-Manager (LCM) by HomeAccessoryKid (@HomeACcessoryKid), licensed under Apache License 2.0.
 * https://github.com/HomeACcessoryKid/life-cycle-manager
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <esp/uart.h>
#include <esp8266.h>
#include <FreeRTOS.h>
#include <task.h>

#include <espressif/esp_common.h>

#include <wifi_config.h>
#include <sysparam.h>

#include <rboot-api.h>

#include <adv_logger.h>

#include "ota.h"
#include "header.h"

char* user_repo = NULL;
char* user_version = NULL;

char* new_version = NULL;
char* ota_version = NULL;
char* stored_ota_version = NULL;
byte signature[SIGNSIZE];
int file_size = 0;

uint8_t tries_count = 0;

void ota_task(void *arg) {
#ifdef HAABOOT
    printf("\n*******************************\n* ESPY House Installer %s\n*******************************\n\n", OTAVERSION);
    sysparam_set_string(USER_VERSION_SYSPARAM, "none");
#else
    printf("\n*******************************\n* ESPY House OTA %s\n*******************************\n\n", OTAVERSION);
#endif

    sysparam_status_t status;
    status = sysparam_get_string(CUSTOM_REPO_SYSPARAM, &user_repo);
    if (status != SYSPARAM_OK || strcmp(user_repo, "") == 0) {
        user_repo = REPOSITORY;
    }
    printf("Repository: %s\n", user_repo);

    status = sysparam_get_string(USER_VERSION_SYSPARAM, &user_version);
    if (status == SYSPARAM_OK) {
        printf("Current HAAMAIN version installed: %s\n", user_version);

        ota_init(user_repo);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        sysparam_set_int8(HAA_SETUP_MODE_SYSPARAM, 0);
        for (;;) {
            printf("\n*** STARTING UPDATE PROCESS\n\n");
            tries_count++;
#ifdef HAABOOT
            if (ota_get_sign(user_repo, OTAMAINFILE, signature) > 0) {
                file_size = ota_get_file(user_repo, OTAMAINFILE, BOOT1SECTOR);
                if (file_size > 0 && ota_verify_sign(BOOT1SECTOR, file_size, signature) == 0) {
                    ota_finalize_file(BOOT1SECTOR);
                    printf("\n*** OTAMAIN installed\n\n");
                    sysparam_set_int8(HAA_SETUP_MODE_SYSPARAM, 0);
                    rboot_set_temp_rom(1);
                    ota_reboot();
                } else {
                    printf("\n!!! Error installing OTAMAIN\n\n");
                    sysparam_set_int8(HAA_SETUP_MODE_SYSPARAM, 1);
                }
            } else {
                printf("\n!!! Error downloading OTAMAIN signature\n\n");
                sysparam_set_int8(HAA_SETUP_MODE_SYSPARAM, 1);
            }
#else   // HAABOOT
            int compare_ota_version;

            if (ota_version == NULL) ota_version = ota_get_version(user_repo, OTAVERSIONFILE);
            if (ota_version == NULL) break; // Cannot get remote version

            status = sysparam_get_string(OTA_VERSION_SYSPARAM, &stored_ota_version);
            if (status == SYSPARAM_OK) {
                compare_ota_version = strcmp(ota_version, stored_ota_version);
            } else {
                stored_ota_version = OTAVERSION;
            }
            printf("\n*** Server version: [%s], local version [%s]\n", ota_version, stored_ota_version);
            compare_ota_version = strcmp(ota_version, stored_ota_version);
            if (status == SYSPARAM_OK) free(stored_ota_version);

            if (ota_version && compare_ota_version != 0) {
                if (ota_get_sign(user_repo, OTABOOTFILE, signature) > 0) {
                    file_size = ota_get_file(user_repo, OTABOOTFILE, BOOT0SECTOR);
                    if (file_size > 0 && ota_verify_sign(BOOT0SECTOR, file_size, signature) == 0) {
                        ota_finalize_file(BOOT0SECTOR);
                        sysparam_set_string(OTA_VERSION_SYSPARAM, ota_version);
                        printf("\n*** HAABOOT v%s installed\n\n", ota_version);
                    } else {
                        printf("\n!!! Error installing HAABOOT\n\n");
                    }
                    break;
                } else {
                    printf("\n!!! Error downloading HAABOOT signature\n\n");
                }
            }
            if (new_version) {
                free(new_version);
                new_version = NULL;
            }
            new_version = ota_get_version(user_repo, HAAVERSIONFILE);
            printf("\n*** Server version: [%s], local version [%s]\n\n", new_version, user_version);
            if (new_version && strcmp(new_version, user_version) != 0) {
                if (ota_get_sign(user_repo, HAAMAINFILE, signature) > 0) {
                    file_size = ota_get_file(user_repo, HAAMAINFILE, BOOT0SECTOR);
                    if (file_size > 0 && ota_verify_sign(BOOT0SECTOR, file_size, signature) == 0) {
                        ota_finalize_file(BOOT0SECTOR);
                        sysparam_set_string(USER_VERSION_SYSPARAM, new_version);
                        printf("\n*** HAAMAIN v%s installed\n\n", new_version);
                    } else {
                        printf("\n!!! Error installing HAAMAIN\n\n");
                    }
                } else {
                    printf("\n!!! Error downloading HAAMAIN signature\n\n");
                }
            }
            break;
#endif  // HAABOOT
            if (tries_count == MAX_TRIES) {
                break;
            }
            vTaskDelay(5000 / portTICK_PERIOD_MS);
        }
    }
    ota_reboot();
}

void on_wifi_ready() {
    xTaskCreate(ota_task, "ota_task", 4096, NULL, 1, NULL);
}

void user_init(void) {
    sdk_wifi_set_opmode(STATION_MODE);
    sdk_wifi_station_disconnect();
    uart_set_baud(0, 115200);
    adv_logger_init(ADV_LOGGER_UART0_UDP);
    printf("\n\n\n");
    sysparam_status_t status;

    status = sysparam_init(SYSPARAMSECTOR, 0);
    if (status == SYSPARAM_NOTFOUND) {
        printf("Sysparam not found, creating...\n");
        status = sysparam_create_area(SYSPARAMSECTOR, SYSPARAMSIZE, true);
        if (status == SYSPARAM_OK) {
            printf("Sysparam created\n");
            status = sysparam_init(SYSPARAMSECTOR, 0);
        }
    }
    if (status == SYSPARAM_OK) {
        printf("Sysparam OK\n\n");
    } else {
        printf("! Sysparam %d\n", status);
    }
    wifi_config_init("ESPY", NULL, on_wifi_ready);
}
