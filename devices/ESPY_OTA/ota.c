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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <esp8266.h>
#include <http-parser/http_parser.h>
#include <lwip/sockets.h>
#include <lwip/api.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <ota.h>

// #include <sntp.h>
#include <spiflash.h>
#include <sysparam.h>
#include <rboot-api.h>

#include <form_urlencoded.h>

#include "header.h"

// Public key to verify signatures
static const byte raw_public_key[] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
    0x03, 0x62, 0x00, 0x04, 0xd4, 0x23, 0x58, 0x4e, 0x23, 0xd8,
    0x64, 0x81, 0x20, 0xc1, 0xf7, 0x7b, 0xd0, 0x47, 0x7a, 0xec,
    0xc0, 0x68, 0x86, 0x1d, 0xf2, 0x8d, 0x1d, 0x96, 0x98, 0x10,
    0x93, 0xd3, 0x73, 0x00, 0x13, 0xc2, 0x3d, 0x5e, 0xc7, 0x66,
    0xfe, 0x1b, 0x09, 0xce, 0x4a, 0xc6, 0x7f, 0x25, 0x25, 0xf0,
    0x06, 0x96, 0x38, 0xf6, 0xf0, 0xf2, 0xef, 0xf3, 0x26, 0x69,
    0x25, 0x8c, 0x90, 0x56, 0xce, 0xd4, 0x5c, 0x09, 0x56, 0x73,
    0xbc, 0x90, 0xf2, 0x81, 0x27, 0xcf, 0x14, 0xe5, 0xbe, 0xcf,
    0x09, 0xce, 0xed, 0x3d, 0xca, 0xad, 0xd3, 0x6f, 0xd7, 0x58,
    0xc7, 0x12, 0xa0, 0x3d, 0x68, 0x22, 0xb8, 0x0c, 0x10, 0x1b
};

static ecc_key public_key;
static byte file_first_byte[] = { 0xff };
static WOLFSSL_CTX* ctx;
static int local_port = 0;
static char last_host[HOST_LEN];
static char last_request[PATH_LEN];
static int  last_port = 0;
static bool last_ssl = false;

#ifdef DEBUG_WOLFSSL
void wolfssl_logging_callback(const int level, const char* const message) {
    printf("[%d] %s\n", level, message);
}
#endif

static int ota_parse_url(const char* url, struct http_parser_url *u, bool redirect) {
#ifdef DEBUG_HTTP
    printf("ota_parse_url: url=[%s]\n", url);
#endif
    http_parser_url_init(u);
    if (http_parser_parse_url(url, strlen(url), 0, u) < 0) return -1; // Parsing error

    if ((u->field_set & (1 << UF_SCHEMA))) {
#ifdef DEBUG_HTTP
        printf("ota_parse_url: parsed schema=[%.*s]\n", u->field_data[UF_SCHEMA].len, url + u->field_data[UF_SCHEMA].off);
#endif
        if ((u->field_data[UF_SCHEMA].off != 0) || (strstr(url, "http") != url)) return -2; // Wrong schema

        if (url[4] == 's') {
            last_ssl = true;
        } else {
            last_ssl = false;
        }
    } else {
        return -2; // Wrong schema
    }

    if ((u->field_set & (1 << UF_HOST))) {
        if (u->field_data[UF_HOST].len + 1 > HOST_LEN) return -3; // Host buffer overflow
        strncpy(last_host, url + u->field_data[UF_HOST].off, u->field_data[UF_HOST].len);
        last_host[u->field_data[UF_HOST].len] = 0;
    } else {
        last_host[0] = 0;
    }

    if ((u->field_set & (1 << UF_PATH))) {
        if (u->field_data[UF_PATH].len + 1 > PATH_LEN) return -4; // Path buffer overflow
        strncpy(last_request, url + u->field_data[UF_PATH].off, u->field_data[UF_PATH].len);
        last_request[u->field_data[UF_PATH].len] = 0;
    } else {
        strcpy(last_request, "/");
    }

    if ((u->field_set & (1 << UF_PORT))) {
        last_port = u->port;
    } else {
        if (last_ssl) {
            last_port = 443;
        } else {
            last_port = 80;
        }
    }

    if (redirect) {
        int len = strlen(last_request) + u->field_data[UF_QUERY].len + 2;
        if (len > PATH_LEN) return -5; // Query buffer overflow
        strcat(last_request, "?");
        strncat(last_request, url + u->field_data[UF_QUERY].off, u->field_data[UF_QUERY].len);
        last_request[len-1] = 0;
    } else {
        if (!strcmp(last_host, "github.com")) { // Fix github.com path
            if (last_request[strlen(last_request)-1] != '/') strcat(last_request, "/");
            strcat(last_request, "releases/latest/download");
        }
    }

#ifdef DEBUG_HTTP
    printf("ota_parse_url: host=[%s] port=[%d] ssl=[%s] request=[%s]\n", last_host, last_port, (last_ssl ? "t" : "f"), last_request);
#endif

    return 0;
}

int ota_resolve(char* host, ip_addr_t* ip) {
    int ret;

    for (int i = 1; i <= MAX_DNS_TRIES; i++) {
        if ((ret = netconn_gethostbyname(host, ip)) == ERR_OK) break;
        printf("! ERROR DNS try #%d failed (err: %d)\n", i, ret);
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    return ret;
}

void ota_init(char* repo) {
    ip_addr_t target_ip;
    struct http_parser_url u;
    int err;

    //rboot setup
    rboot_config conf;
    conf = rboot_get_config();
    if (conf.count != 2 || conf.roms[0] != BOOT0SECTOR || conf.roms[1] != BOOT1SECTOR || conf.current_rom != 0) {
        conf.count = 2;
        conf.roms[0] = BOOT0SECTOR;
        conf.roms[1] = BOOT1SECTOR;
        conf.current_rom = 0;
        rboot_set_config(&conf);
    }

    if ((err = ota_parse_url(repo, &u, false)) < 0) {
        printf("! Wrong repository, err=%d\n", err);
        ota_reboot();
        return;
    }

    if (last_ssl) {
/*
        // Time support
        const char *servers[] = { SNTP_SERVERS };
        sntp_set_update_delay(24 * 60 * 60000);     // SNTP will request an update every 24 hour

        sntp_initialize(NULL);
        sntp_set_servers(servers, sizeof(servers) / sizeof(char*));     // Servers must be configured right after initialization
*/
#ifdef DEBUG_WOLFSSL
        if (wolfSSL_SetLoggingCb(wolfssl_logging_callback)) {
            printf("! WolfSSL cannot set logging callback\n");
        }
#endif
        wolfSSL_Init();

        if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
            printf("! WolfSSL CTX_new error\n");
        }
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    printf("DNS check result = ");
    if (ota_resolve(last_host, &target_ip)) {
        printf("ERROR\n");
        ota_reboot();
        return;
    }

    word32 idx = 0;
    wc_ecc_init(&public_key);
    wc_EccPublicKeyDecode(raw_public_key, &idx, &public_key, sizeof(raw_public_key));

    printf("OK\n");
}

static int ota_connect(int *socket, WOLFSSL** ssl) {
    printf("Connect: localPort=");
    int ret;
    ip_addr_t target_ip;
    struct sockaddr_in sock_addr;
    unsigned char initial_port[2];
    WC_RNG rng;
    if (!local_port) {
        wc_RNG_GenerateBlock(&rng, initial_port, 2);
        local_port = (256 * initial_port[0] + initial_port[1]) | 0xc000;
    }
    printf("%d, remotePort=%d hostName=%s DNS=", local_port, last_port, last_host);
    if (ota_resolve(last_host, &target_ip)) {
        printf(FAILED);
        return -2;
    }
    printf("OK ");
    printf("IP=%d.%d.%d.%d ", (unsigned char) ((target_ip.addr & 0x000000ff) >> 0),
                              (unsigned char) ((target_ip.addr & 0x0000ff00) >> 8),
                              (unsigned char) ((target_ip.addr & 0x00ff0000) >> 16),
                              (unsigned char) ((target_ip.addr & 0xff000000) >> 24));

    *socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*socket < 0) {
        printf(FAILED);
        return -3;
    }

    printf("localSocket=");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = 0;
    sock_addr.sin_port = htons(local_port++);
    if (local_port == 0x10000) {
        local_port = 0xc000;
    }
    ret = bind(*socket, (struct sockaddr*) &sock_addr, sizeof(sock_addr));
    if (ret) {
        printf(FAILED);
        return -2;
    }
    printf("OK ");

    printf("remoteSocket=");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = target_ip.addr;
    sock_addr.sin_port = htons(last_port);
    ret = connect(*socket, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret) {
        printf(FAILED);
        return -2;
    }
    printf("OK ");

    if (last_ssl) {   // SSL mode
        printf("SSL=");
        *ssl = wolfSSL_new(ctx);
        if (!*ssl) {
            printf(FAILED);
            return -2;
        }
        printf("OK ");

#ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_ON();
#endif
        wolfSSL_set_fd(*ssl, *socket);
        printf("set_fd ");

        ret = wolfSSL_check_domain_name(*ssl, last_host);
#ifdef DEBUG_WOLFSSL
        wolfSSL_Debugging_OFF();
#endif

        printf("host=%s port=%d ", last_host, last_port);
        ret = wolfSSL_connect(*ssl);
        if (ret != SSL_SUCCESS) {
            printf("wolfSSL error = %d (%d)\n", wolfSSL_get_error(*ssl, ret), ret);
            return -1;
        }
        printf("OK");
    }
    printf("\n");
    return 0;
}

static int ota_get_file_ex(char* repo, char* file, int sector, byte* buffer, int bufsz) { // Returns number of bytes downloaded
    int connect_status, result = 0;
    WOLFSSL* ssl;
    int socket;

    char recv_buf[RECV_BUF_LEN + 1];
    int buf_space_avail;
    int content_length;
    int full_length;
    int left;
    int recv_bytes;
    int written = 0;
    double percent;
    char *p;
    bool header;
    uint8_t redirect_count = 0;
    uint16_t http_reply_code;
    struct http_parser_url u;

    if (!sector && buffer == NULL) return -5; // Needs to be either a sector or a signature/version file
    if (buffer != NULL) buffer[0] = 0;

    if (ota_parse_url(repo, &u, false) < 0) return -4; // Repository parse error

    // Add file to path
    if (last_request[strlen(last_request)-1] != '/') strcat(last_request, "/");
    strcat(last_request, file);


    printf("\n* Download file: http%s://%s%s\n", (last_ssl ? "s" : ""), last_host, last_request);

    while (redirect_count < MAX_REDIRECTS) {
        redirect_count++;

        connect_status = ota_connect(&socket, &ssl);
        if (!connect_status) {
            const uint16_t http_request_max_len = 37 + strlen(last_host) + strlen(last_request);
            char *http_request = malloc(http_request_max_len);
            snprintf(http_request, http_request_max_len,
                     REQUESTHEAD"%s"REQUESTTAIL"%s"RANGE,
                     last_request, last_host);

            buf_space_avail = 0;
            content_length = 0;
            full_length = 1;
            written = 0;
            while (written < full_length) {
                uint16_t http_request_len = sprintf(recv_buf, "%s%d-%d%s", http_request, written, written + SECTOR_SIZE - 1, CRLFCRLF);
                if (last_ssl) {
                    result = wolfSSL_write(ssl, recv_buf, http_request_len);
                } else {
                    result = lwip_write(socket, recv_buf, http_request_len);
                }
#ifdef DEBUG_HTTP
                recv_buf[http_request_len-3] = 0;
                printf("-[ REQUEST ]----\n%s\n----------------\n", recv_buf);
#endif
                recv_bytes = 0;
                if (result > 0) {
                    header = true;
                    http_reply_code = 0;
                    do {
                        if (last_ssl) {
#ifdef DEBUG_WOLFSSL
                            wolfSSL_Debugging_ON();
#endif
                            result = wolfSSL_read(ssl, recv_buf, RECV_BUF_LEN);
                        } else {
                            result = lwip_read(socket, recv_buf, RECV_BUF_LEN);
                        }
                        if (result > 0) {
                            if (header) {
                                p = strchr(recv_buf+8, ' ') + 1;
                                if ( (strstr(recv_buf, "HTTP") != recv_buf) || (p == NULL) ) {
                                    printf("\n! ERROR Wrong protocol\n");
                                    full_length = 0;
                                    redirect_count = MAX_REDIRECTS;
                                    break;
                                }
                                http_reply_code = atoi(p);

                                if (http_reply_code >= 300 && http_reply_code < 400) {
                                    p = strcasestr(recv_buf, "\nLocation: ");
                                    if (p == NULL) {
                                        printf("\n! ERROR No Location header found\n");
                                        full_length = 0;
                                        redirect_count = MAX_REDIRECTS;
                                        break;
                                    }
                                    strchr(p, '\r')[0] = 0;

                                    p += 11; // Skip "\nLocation: "
                                    while (p[0] == ' ') p++;

                                    bool before_redirect_ssl = last_ssl;

                                    if (ota_parse_url(p, &u, true) < 0) {
                                        printf("\n! ERROR Cannot parse URL\n");
                                        full_length = 0;
                                        redirect_count = MAX_REDIRECTS;
                                        break;
                                    }

                                    if (!before_redirect_ssl && last_ssl && (redirect_count < MAX_REDIRECTS)) { // Redirect http -> https
                                        connect_status = -2; // Clear old socket, don't try to clear not created yet SSL
                                        last_ssl = true;

                                        wolfSSL_Init();
                                        if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
                                            printf("! WolfSSL CTX_new error\n");
                                        }
                                        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
                                    }

                                    if (before_redirect_ssl && !last_ssl) { // Redirect https -> http
                                        printf("\n! ERROR Redirect https -> http not allowed\n");
                                        full_length = 0;
                                        redirect_count = MAX_REDIRECTS;
                                        break;
                                    }

#ifdef DEBUG_HTTP
                                    printf("HTTP reply code %d, redirect #%d to: %s\n", http_reply_code, redirect_count, p);
#else
                                    printf("HTTP reply code %d, redirect #%d to: http%s://%s\n", http_reply_code, redirect_count, (last_ssl ? "s" : ""), last_host);
#endif
                                    full_length = 0;
                                    break;
                                }

                                if (http_reply_code >= 400) {
                                    printf("HTTP negative response, reply code %d\n", http_reply_code);
                                    full_length = 0;
                                    redirect_count = MAX_REDIRECTS;
                                    break;
                                }

                                // Parse Content-Length header
                                p = strcasestr(recv_buf, "\nContent-Length:");
                                if (p == NULL) {
                                    printf("\n! ERROR No Content-Length header found\n");
                                    full_length = 0;
                                    redirect_count = MAX_REDIRECTS;
                                    break;
                                }
                                p += 16; // Skip "Content-Length: "
                                content_length = atoi(p);

                                // Parse Content-Range header
                                p = strcasestr(recv_buf, "\nContent-Range:");
                                if (p == NULL) {
                                    if (buffer) {
                                        full_length = content_length;
                                    } else {
                                        printf("\n! ERROR No Content-Range header found\n");
                                        full_length = 0;
                                        redirect_count = MAX_REDIRECTS;
                                        break;
                                    }
                                }
                                p += 15; // Skip "Content-Range: "
                                p = strcasestr(recv_buf, "bytes ");
                                p += 6; // Skip "bytes "
                                p = strstr(p, "/");
                                p++; // Skip "/"
                                full_length = atoi(p);

                                p = strstr(recv_buf, CRLFCRLF); // Search for end of headers
                                if (p == NULL) {
                                    printf("\n! ERROR Buffer is not enough for HTTP headers\n");
                                    full_length = 0;
                                    redirect_count = MAX_REDIRECTS;
                                    break;
                                }
#ifdef DEBUG_HTTP
                                p[0] = 0;
                                printf("-[ REPLY ]------\n%s\n----------------\n", recv_buf);
#endif
                                p += 4;

                                if ((left = result - (p - recv_buf))) {
                                    header = false; // We have body in the same IP packet as the header so we need to process it already
                                    result = left;
                                    memmove(recv_buf, p, left); // Move this payload to the head of the recv_buf
                                }
                            }
                            if (!header) {
                                if (sector) { // Write to flash
                                    if (buf_space_avail < result) {
                                        printf("Sector 0x%05x ", sector + written);
                                        if (!spiflash_erase_sector(sector + written)) return -6; // Erase error
                                        buf_space_avail += SECTOR_SIZE;
                                    }
                                    if (written) {
                                        if (!spiflash_write(sector + written, (byte *)recv_buf, result)) return -7; // Write error
                                    } else { // At the very beginning, do not write the first byte yet but store it for later
                                        file_first_byte[0] = (byte)recv_buf[0];
                                        if (!spiflash_write(sector + 1, (byte *)recv_buf + 1, result - 1)) return -7; // Write error
                                    }
                                    buf_space_avail -= result;
                                } else { // Buffer
                                    if (result > bufsz) return -8; // Too big
                                    memcpy(buffer, recv_buf, result);
                                }
                                recv_bytes += result;
                                written += result;
                            }
                        } else {
                            if (result < 0 && last_ssl) printf("! wolfSSL read error = %d\n", wolfSSL_get_error(ssl, result));
                            if (!result && written < full_length) connect_status = ota_connect(&socket, &ssl);
                            break;
                        }
                        header = false;
                    } while (recv_bytes < content_length);
                    if (http_reply_code >= 200 && http_reply_code < 300) {
                        percent = 100*written/full_length;
                        if (recv_bytes == content_length) redirect_count = MAX_REDIRECTS;
                        printf("Downloaded: %d of %d bytes, %.0lf%%\n", written, full_length, percent);
                    }
                } else {
                    printf("! Write error = %d\n", result);
                    if (last_ssl) {
                        printf("! wolfSSL write error = %d\n", wolfSSL_get_error(ssl, result));
                        if (result == SOCKET_ERROR_E) {
                            connect_status = ota_connect(&socket, &ssl);
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            free(http_request);
        } else {
            printf("! Connection failed, error = %d\n", result);
            if (last_ssl) printf("! wolfSSL error = %d\n", wolfSSL_get_error(ssl, result));
            redirect_count = MAX_REDIRECTS;
        }
        switch (connect_status) {
            case 0:
            case -1:
                if (last_ssl) wolfSSL_free(ssl);
            case -2:
                lwip_close(socket);
            case -3:
            default:
            ;
        }
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#pragma GCC diagnostic pop

    return written;
}

int ota_get_file(char* repo, char* file, int sector) {
    return ota_get_file_ex(repo, file, sector, NULL, 0);
}

char* ota_get_version(char* repo, char* version_file) {
    byte* version = malloc(VERSIONFILESIZE + 1);
    memset(version, 0, VERSIONFILESIZE + 1);

    if (!ota_get_file_ex(repo, version_file, 0, version, VERSIONFILESIZE)) {
        free(version);
        version = NULL;
        printf("! Cannot get remote version\n");
    }
    return (char*) version;
}

int ota_get_sign(char* repo, char* file, byte* signature) {
    int ret;
    char* signame = malloc(strlen(file) + 5);
    strcpy(signame, file);
    strcat(signame, SIGNFILESUFIX);
    memset(signature, 0, SIGNSIZE);
    ret = ota_get_file_ex(repo, signame, 0, signature, SIGNSIZE);
    free(signame);
    return ret;
}

int ota_verify_sign(int start_sector, int filesize, byte* signature) {
    printf("Verify signature\n");
    int bytes;
    byte hash[HASHSIZE];
    byte buffer[1024];
    Sha384 sha;
    wc_InitSha384(&sha);

    for (bytes = 0; bytes < filesize - 1024; bytes += 1024) {
        if (!spiflash_read(start_sector + bytes, (byte*) buffer, 1024)) {
            printf("! Reading flash\n");
            break;
        }
        if (!bytes) buffer[0] = file_first_byte[0];
        wc_Sha384Update(&sha, buffer, 1024);
    }

    if (!spiflash_read(start_sector + bytes, (byte*) buffer, filesize - bytes)) {
        printf("! Reading flash\n");
    }
    wc_Sha384Update(&sha, buffer, filesize - bytes);
    wc_Sha384Final(&sha, hash);
    int verify = 0;
    wc_ecc_verify_hash(signature, SIGNSIZE, hash, HASHSIZE, &verify, &public_key);
    printf("Sign result: %s (%d)\n", verify == 1 ? "OK" : "ERROR" , verify);

    return verify - 1;
}

void ota_finalize_file(int sector) {
    printf("Finalize file\n");

    if (!spiflash_write(sector, file_first_byte, 1))
        printf("! Writing flash\n");
}

void ota_reboot() {
    printf("\nRestarting...\n");

    vTaskDelay(1000 / portTICK_PERIOD_MS);
    sdk_system_restart();
}

