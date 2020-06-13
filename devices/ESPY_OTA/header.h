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
 */

#ifndef __ESPY_OTA_HEADER_H__
#define __ESPY_OTA_HEADER_H__

#define OTAVERSION              "1.0.2"

#define CUSTOM_REPO_SYSPARAM     "ota_server"
#define OTA_VERSION_SYSPARAM     "ota_repo"
#define USER_VERSION_SYSPARAM    "ota_version"
#define WIFI_SSID_SYSPARAM       "wifi_ssid"
#define WIFI_PASSWORD_SYSPARAM   "wifi_password"
#define WIFI_MODE_SYSPARAM       "wifi_mode"
#define WIFI_BSSID_SYSPARAM      "wifi_bssid"
#define AUTO_OTA_SYSPARAM        "aota"
#define TOTAL_ACC_SYSPARAM       "total_ac"
#define ESPY_JSON_SYSPARAM       "conf"
#define ESPY_SETUP_MODE_SYSPARAM "setup"

#endif  // __ESPY_OTA_HEADER_H__
