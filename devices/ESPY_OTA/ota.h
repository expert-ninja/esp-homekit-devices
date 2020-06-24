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

#ifndef __ESPY_OTA_H__
#define __ESPY_OTA_H__

#define REPOSITORY              "https://github.com/expert-ninja/espy-house"
#define OTAMAINFILE             "espy_ota.bin"
#define OTABOOTFILE             "espy_installer.bin"
#define ESPYMAINFILE            "espy_house.bin"
#define OTAVERSIONFILE          "espy_ota.ver"
#define ESPYVERSIONFILE         "espy_house.ver"
#define SIGNFILESUFIX           ".sign"
#define VERSIONFILESIZE         9

#define MAX_TRIES               2

#define SYSPARAMSECTOR          0xF3000
#define SYSPARAMSIZE            8

#define BOOT0SECTOR             0x02000
#define BOOT1SECTOR             0x8D000     // Must match the program1.ld value

#define HTTPS_PORT              443
#define FAILED                  "failed\n"
#define REQUESTHEAD             "GET "
#define REQUESTTAIL             " HTTP/1.1\r\nHost: "
#define CRLFCRLF                "\r\n\r\n"
#define RECV_BUF_LEN            2048
#define HOST_LEN                256
#define PATH_LEN                1024
#define RANGE                   "\r\nRange: bytes="

#define SNTP_SERVERS            "0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org", "3.pool.ntp.org"
#define MAX_REDIRECTS           10
#define MAX_DNS_TRIES           3

#define HASHSIZE                48      //SHA-384
#define SIGNSIZE                104     //ECDSA r+s in ASN1 format secP384r1

typedef unsigned char byte;

void ota_init(char* repo);
char* ota_get_version(char* repo, char* version_file);
int ota_get_file(char* repo, char* file, int sector);
void ota_finalize_file(int sector);
int ota_get_sign(char* repo, char* file, byte* signature);
int ota_verify_sign(int address, int file_size, byte* signature);
void ota_reboot();

#endif // __ESPY_OTA_H__
