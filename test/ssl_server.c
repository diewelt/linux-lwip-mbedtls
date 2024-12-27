/*
 *  SSL server demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include "lwipopts.h"      // KYLE
#include "arch/sys_arch.h" // KYLE
#include "lwip/sockets.h"  // KYLE

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
//#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>Mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#if 0
/* self signed CA + server certificate */
#define TEST_CA_CRT_RSA_SHA256_PEM                                             \
    "-----BEGIN CERTIFICATE-----\r\n"                                          \
    "MIID9TCCAt2gAwIBAgIUNAp01Nr0kE+tZegJo9y1rTPZqMkwDQYJKoZIhvcNAQEL\r\n"     \
    "BQAwgYkxCzAJBgNVBAYTAkFVMQwwCgYDVQQIDANOU1cxDzANBgNVBAcMBlNlZnRv\r\n"     \
    "bjEPMA0GA1UECgwGQUNFbXVtMQwwCgYDVQQLDANkZXYxFjAUBgNVBAMMDWFjZW11\r\n"     \
    "bS5jb20uYXUxJDAiBgkqhkiG9w0BCQEWFWt5bGUucy5zaGltQGdtYWlsLmNvbTAe\r\n"     \
    "Fw0yNDEyMjQwMjA1MDdaFw0yOTEyMjMwMjA1MDdaMIGJMQswCQYDVQQGEwJBVTEM\r\n"     \
    "MAoGA1UECAwDTlNXMQ8wDQYDVQQHDAZTZWZ0b24xDzANBgNVBAoMBkFDRW11bTEM\r\n"     \
    "MAoGA1UECwwDZGV2MRYwFAYDVQQDDA1hY2VtdW0uY29tLmF1MSQwIgYJKoZIhvcN\r\n"     \
    "AQkBFhVreWxlLnMuc2hpbUBnbWFpbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB\r\n"     \
    "DwAwggEKAoIBAQC4Ve2tylgEqAFZCsD80PajhWpqInSehV/2Y5sQ4Ddfy20ELkl6\r\n"     \
    "7dsKCRngdErRk/0rUus2e9fYTr4gEjgD2MBhbkbdOkkvCEu7tY6DaqxiiNEGuEWi\r\n"     \
    "UoI44Yj6D8BPilkr8dQSce4spDBc9nFm0ilukZFL11CM3k0Cs2qYX7SloOCavJD0\r\n"     \
    "Z304Fmpg6/cI6m1wHFnyCIaRUaTC43UeU1LwTUBYj9tr/3cMWGDNWMrtn+PKjxZ7\r\n"     \
    "5nCtPxS2Rp64xv/1yuOkFCsRTk0SqPCWCR2HFHEIqv/C8YtYxrbO7nVt6mAmS5Xy\r\n"     \
    "Bl13Pw6b8AyPkVyQzjICRUeNwU6Qes+ugw3VAgMBAAGjUzBRMB0GA1UdDgQWBBRH\r\n"     \
    "qcbc2i7G0obkXeRVBupuN3bgWTAfBgNVHSMEGDAWgBRHqcbc2i7G0obkXeRVBupu\r\n"     \
    "N3bgWTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCWFJERWt8P\r\n"     \
    "LTZPjfntm2xDYsIB7GhFZ3t+YDEHE+DqH206ozOgCoQvPdb8c6Jmh+ocJ+7hsNY1\r\n"     \
    "BT/FLw9OngvNF+lTzlonr8ulI6SE45BsSmTKyT/f8vpTpGi+TTFydBv5ZatIvoLQ\r\n"     \
    "N8/dxDm5t5x7EehP6glBB4Ur/ybtqj4NUG4ihQIz7E+MeNEuDUzDX/jnrsNadJiJ\r\n"     \
    "08rOwOR0X3hI2FJQ1WUpPRkLBU6O4qZd00YC8bvgY9DhZnU/7TBga/f2tIz4tWyz\r\n"     \
    "siKKJB9U4JJfvSER+tr9+yUBnjDb1uXFvW1OfT+JA4M3eDwG8KiWSBE8pUpl446T\r\n"     \
    "4ODs23pHLjLI\r\n"                                                         \
    "-----END CERTIFICATE-----\r\n"
#else
/* in case of self signed CA + intermediate CA +  server certificate */
/* intermediate CA + self signed CA for CA certificates in order */
#define TEST_CA_CRT_RSA_SHA256_PEM                                             \
    "-----BEGIN CERTIFICATE-----\r\n"                                          \
    "MIIDvjCCAqagAwIBAgICEAQwDQYJKoZIhvcNAQELBQAwgYkxCzAJBgNVBAYTAkFV\r\n"     \
    "MQwwCgYDVQQIDANOU1cxDzANBgNVBAcMBlNlZnRvbjEPMA0GA1UECgwGQUNFbXVt\r\n"     \
    "MQwwCgYDVQQLDANkZXYxFjAUBgNVBAMMDWFjZW11bS5jb20uYXUxJDAiBgkqhkiG\r\n"     \
    "9w0BCQEWFWt5bGUucy5zaGltQGdtYWlsLmNvbTAeFw0yNDEyMjcwMzAwNDVaFw0z\r\n"     \
    "NDEyMjUwMzAwNDVaMFIxCzAJBgNVBAYTAkFVMQwwCgYDVQQIDANOU1cxDzANBgNV\r\n"     \
    "BAcMBlN5ZG5leTERMA8GA1UECgwIaW50ZXJDQTIxETAPBgNVBAMMCGludGVyQ0Ey\r\n"     \
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo0Z5Xh8jVHeOq6eX4ZjJ\r\n"     \
    "5xEgoIgjDDZJMKOdyuglgOJtcZe+v+p0jrKGVBgLh6+uQx9WEOE4GvXEJwwNHySS\r\n"     \
    "sRDsZOwvE4/8YVIOut9dBLeep9h6vuJo2qLQCQly+cgIP54MHlByf4s68kyjqwNg\r\n"     \
    "7d3yxziOKriAnx9n7I/bIVwATn4QLy6SYZFhIgn0mbgtH7YeIG4H8/h1W96cb8LI\r\n"     \
    "jimKyrQzzjJY2eo9KWVYBL2SNNRCh8u2UAYZht9Z//6XzXGAzQ4oi9sxjMN14KKD\r\n"     \
    "3sM3qEvbSDbRbf15LE/6LavkUGvNx2YWTimhzaGfKF6BUGk7LUxxHvh/iH8T+W9N\r\n"     \
    "sQIDAQABo2YwZDAdBgNVHQ4EFgQUSJ88R3YOuPd0hvSH5oGuS4robT8wHwYDVR0j\r\n"     \
    "BBgwFoAUR6nG3NouxtKG5F3kVQbqbjd24FkwEgYDVR0TAQH/BAgwBgEB/wIBADAO\r\n"     \
    "BgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggEBAEX3RB0G8VlIF0sELU5d\r\n"     \
    "e48/YPliaEvzZ9y+MuD2Yb5K+gRUNDub4aOIhKAlpUzp8CGvXgeCxU/mC8ziARoL\r\n"     \
    "ZkB9Qo2Rxefi7voxQOxDkMd8ePu12P9plsjXcax5Kp/948fhM4QFRl5BxF/7jGVc\r\n"     \
    "lEGDorkz1U5ZtXGpeGfPwpQsrmBypydc1WM6o+Z9PhXQphN1/OhpD2BenWaY/TxQ\r\n"     \
    "lCC74TDGqEgvigA4OlkKtK5+0bKNlNtG6ziduikABAaO0THG337TEFMRO1gZAnWN\r\n"     \
    "S8+CzUsB+EGoSDqh6EnXlk5briH+Qgcqgz0GXpFv8tOD6ialxSVPNMJGAUrNy3Z/\r\n"     \
    "DAA=\r\n"                                                                 \
    "-----END CERTIFICATE-----\r\n"                                            \
    "-----BEGIN CERTIFICATE-----\r\n"                                          \
    "MIID9TCCAt2gAwIBAgIUNAp01Nr0kE+tZegJo9y1rTPZqMkwDQYJKoZIhvcNAQEL\r\n"     \
    "BQAwgYkxCzAJBgNVBAYTAkFVMQwwCgYDVQQIDANOU1cxDzANBgNVBAcMBlNlZnRv\r\n"     \
    "bjEPMA0GA1UECgwGQUNFbXVtMQwwCgYDVQQLDANkZXYxFjAUBgNVBAMMDWFjZW11\r\n"     \
    "bS5jb20uYXUxJDAiBgkqhkiG9w0BCQEWFWt5bGUucy5zaGltQGdtYWlsLmNvbTAe\r\n"     \
    "Fw0yNDEyMjQwMjA1MDdaFw0yOTEyMjMwMjA1MDdaMIGJMQswCQYDVQQGEwJBVTEM\r\n"     \
    "MAoGA1UECAwDTlNXMQ8wDQYDVQQHDAZTZWZ0b24xDzANBgNVBAoMBkFDRW11bTEM\r\n"     \
    "MAoGA1UECwwDZGV2MRYwFAYDVQQDDA1hY2VtdW0uY29tLmF1MSQwIgYJKoZIhvcN\r\n"     \
    "AQkBFhVreWxlLnMuc2hpbUBnbWFpbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB\r\n"     \
    "DwAwggEKAoIBAQC4Ve2tylgEqAFZCsD80PajhWpqInSehV/2Y5sQ4Ddfy20ELkl6\r\n"     \
    "7dsKCRngdErRk/0rUus2e9fYTr4gEjgD2MBhbkbdOkkvCEu7tY6DaqxiiNEGuEWi\r\n"     \
    "UoI44Yj6D8BPilkr8dQSce4spDBc9nFm0ilukZFL11CM3k0Cs2qYX7SloOCavJD0\r\n"     \
    "Z304Fmpg6/cI6m1wHFnyCIaRUaTC43UeU1LwTUBYj9tr/3cMWGDNWMrtn+PKjxZ7\r\n"     \
    "5nCtPxS2Rp64xv/1yuOkFCsRTk0SqPCWCR2HFHEIqv/C8YtYxrbO7nVt6mAmS5Xy\r\n"     \
    "Bl13Pw6b8AyPkVyQzjICRUeNwU6Qes+ugw3VAgMBAAGjUzBRMB0GA1UdDgQWBBRH\r\n"     \
    "qcbc2i7G0obkXeRVBupuN3bgWTAfBgNVHSMEGDAWgBRHqcbc2i7G0obkXeRVBupu\r\n"     \
    "N3bgWTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCWFJERWt8P\r\n"     \
    "LTZPjfntm2xDYsIB7GhFZ3t+YDEHE+DqH206ozOgCoQvPdb8c6Jmh+ocJ+7hsNY1\r\n"     \
    "BT/FLw9OngvNF+lTzlonr8ulI6SE45BsSmTKyT/f8vpTpGi+TTFydBv5ZatIvoLQ\r\n"     \
    "N8/dxDm5t5x7EehP6glBB4Ur/ybtqj4NUG4ihQIz7E+MeNEuDUzDX/jnrsNadJiJ\r\n"     \
    "08rOwOR0X3hI2FJQ1WUpPRkLBU6O4qZd00YC8bvgY9DhZnU/7TBga/f2tIz4tWyz\r\n"     \
    "siKKJB9U4JJfvSER+tr9+yUBnjDb1uXFvW1OfT+JA4M3eDwG8KiWSBE8pUpl446T\r\n"     \
    "4ODs23pHLjLI\r\n"                                                         \
    "-----END CERTIFICATE-----\r\n"
#endif

#define TEST_SVR_CRT_RSA_SHA256_PEM                                            \
    "-----BEGIN CERTIFICATE-----\r\n"                                          \
    "MIIDcDCCAlgCFGcM2ztPUJnxEjcTh95PHw+nhIhfMA0GCSqGSIb3DQEBCwUAMIGJ\r\n"     \
    "MQswCQYDVQQGEwJBVTEMMAoGA1UECAwDTlNXMQ8wDQYDVQQHDAZTZWZ0b24xDzAN\r\n"     \
    "BgNVBAoMBkFDRW11bTEMMAoGA1UECwwDZGV2MRYwFAYDVQQDDA1hY2VtdW0uY29t\r\n"     \
    "LmF1MSQwIgYJKoZIhvcNAQkBFhVreWxlLnMuc2hpbUBnbWFpbC5jb20wHhcNMjQx\r\n"     \
    "MjI0MDUxNzE3WhcNMjcwMzI5MDUxNzE3WjBfMQswCQYDVQQGEwJBVTEMMAoGA1UE\r\n"     \
    "CAwDTlNXMQ8wDQYDVQQHDAZTZWZ0b24xDzANBgNVBAoMBmFjZW11bTEPMA0GA1UE\r\n"     \
    "CwwGc2VydmVyMQ8wDQYDVQQDDAZzZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IB\r\n"     \
    "DwAwggEKAoIBAQDJ5M/TkbrmCYINr6PtwKKaaRox00izPUctvuc7fpNqdiVJ72zi\r\n"     \
    "zJCXtKw4d5HruPO0U1lLcOAE1Wl/Z87p1CDZc7zuAlnuJohTCCekyb3ZWw5sB2hY\r\n"     \
    "B1ftfF9N6KUAp7ygJ7Ywqy2+AWWtmsLvYLy/sIulje7k7kI6Qpzu61BtT0lEhBW7\r\n"     \
    "Id5KbrvRVdumX8i25Izqm2643FxkFyUDer+vOFFqOlaOaiL8wh5QVOyF3Y8U4NDB\r\n"     \
    "FjKZBH6VB649/IC8Kt8JyEsWJjgfWIwYKx/q0NbyzuPNpsBdQsiyJ8bEAw3TgU/8\r\n"     \
    "+qsL0wiiY0sIbU0gozqwPGuwbxoSRqB7788/AgMBAAEwDQYJKoZIhvcNAQELBQAD\r\n"     \
    "ggEBAHBVq8XT8zXggWyndjxZfXc9T9C5eEfLTShRMu45N//Y7ErrV8HSI4HWkfBO\r\n"     \
    "Z8vzVfS5+VgrN/a6Ai6avt+O1Y7Y5HMhPDq/k7WYwA+EwzIdyqDbfW7DXSD1Aq+8\r\n"     \
    "S7PbT4yTfoWyYuG87Og0WynVN6tYBro2jMvtNAiW9uFzr3+rti7H83MjnTfvY4/X\r\n"     \
    "U0QD/f3yWWeHRI1p3LWfFxFJ/DspiDhE38g1kk3WU0C3xFeuZ2JlJ3AZn55Wss/F\r\n"     \
    "MWmyLx9FaeJoi4SpJ0mtd2Tb/QxubLYogSEhMk4Gp+JgelYkQ7vVOcupGIYnLazV\r\n"     \
    "I6K2kVvD8uPc3ET7FfDlAwVn+k0=\r\n"                                         \
    "-----END CERTIFICATE-----\r\n"

#define TEST_SVR_KEY_RSA_PEM                                                   \
    "-----BEGIN PRIVATE KEY-----\r\n"                                          \
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJ5M/TkbrmCYIN\r\n"     \
    "r6PtwKKaaRox00izPUctvuc7fpNqdiVJ72zizJCXtKw4d5HruPO0U1lLcOAE1Wl/\r\n"     \
    "Z87p1CDZc7zuAlnuJohTCCekyb3ZWw5sB2hYB1ftfF9N6KUAp7ygJ7Ywqy2+AWWt\r\n"     \
    "msLvYLy/sIulje7k7kI6Qpzu61BtT0lEhBW7Id5KbrvRVdumX8i25Izqm2643Fxk\r\n"     \
    "FyUDer+vOFFqOlaOaiL8wh5QVOyF3Y8U4NDBFjKZBH6VB649/IC8Kt8JyEsWJjgf\r\n"     \
    "WIwYKx/q0NbyzuPNpsBdQsiyJ8bEAw3TgU/8+qsL0wiiY0sIbU0gozqwPGuwbxoS\r\n"     \
    "RqB7788/AgMBAAECggEAGfC0xT3JsknRdHm3SdKA8e8EJxe7FRCQBzAqnKnQPhMN\r\n"     \
    "CnlhV6iqAVv87spqLMvYQDifVgKcPfK/udd4LfIMAHSO91PFA0TfKi/3jARByN4a\r\n"     \
    "tcWj4f+bjA95XVTBcpqasUc48Prlhy69xjcGyeP3jHeeEbjxU2fLiZnKeSYx8MFP\r\n"     \
    "IxRh3chQW5nWkjUmfPrw55S5WE+NsG8VV/sIO9phaKSGs9fnntbc+K0y75xurucS\r\n"     \
    "VJOCtMXEVzo6ljtr7GPhHwhLFe1WlKU+1yHbPjUd/s/fHfjlxypiZhpk4ySWpoB3\r\n"     \
    "hsTdlPO2VJkc+aTKVFPVJkADRamMD6slQGOC5EvuJQKBgQDyBXbgZA1XxZ+1Sh/V\r\n"     \
    "6waYlw3w+c5x8wpk7XuXlMI91sjnJThuIgOWEMLzkbF3bRdI/JS30nvFrpO3G/vU\r\n"     \
    "Hja7pLf1p13aoJEv4x43gSErkbZA0Bjglpc1QTB0ZiDWb33i0gYxtaoJSfT5KDEu\r\n"     \
    "DgtGcSBUuDPQERgysvIHYRgKZQKBgQDVjgUrLk49SHCH5wgIjiSM6RxeZ+s44Luc\r\n"     \
    "3QklKDrwYusUdsHOcADz6Ew3p/ZuQudnp3r0F2dNEeKQdixNK8Wpw0x63dHd3INu\r\n"     \
    "CkGVyP5devXkttwFzB3kJGxZkhL0MD8+F1AWuq59S73/0+OGXO0SAgCQdTwKkWTU\r\n"     \
    "kVVw199m0wKBgQDEbrr1lT9fJf9iXS9JqOBJqRCfraFpyyF8mWPeu9aL6nBVa1hJ\r\n"     \
    "y0Gt4xzYJEAt9lUX4Cm0qRnccL1juUrD92HlGuRUdesvL3OnsmcsFZqeij2qjTwj\r\n"     \
    "zRYdGzQAxYORiBxcpKpyXkgMEgLK11xTTQLJwbfEC13CWp2RSLw4UQ36IQKBgCP1\r\n"     \
    "POOPcXcaKnCHsy+Vl4vueGtg/hdep9h6015hTsNJNKIGeQ2kiFSJacP5USIxu7sV\r\n"     \
    "VTuicS9l8os2irEXzLmP++G4Ve0Qg0TVD0QESug8mwi+zX9gZiwTAfd3BB//u7Zd\r\n"     \
    "wIuDNXw9c6mO6QGnxfdBRQ0N4GU7JAoyynssrh4nAoGAIv3H4qTjcHFWtCQsC+Wp\r\n"     \
    "SYD0h4b5C0u+iw2NAoIMQq/QPSe8YMC8G6tr/U6C9PQKSIHqlgRvogKaC5vdLPAA\r\n"     \
    "ZUO9OBSYt/dpFN/8n2WkMfdYpCWLEvnO2eqz0NbwO3fiJOMYw+RiF/l++HeplB1S\r\n"     \
    "xRipHL1/C4YsybnqDewxCnY=\r\n"                                             \
    "-----END PRIVATE KEY-----\r\n"

static const char mbedtls_kyle_cas_pem[] = TEST_CA_CRT_RSA_SHA256_PEM;
static const char mbedtls_kyle_svr_crt[] = TEST_SVR_CRT_RSA_SHA256_PEM;
static const char mbedtls_kyle_svr_key[] = TEST_SVR_KEY_RSA_PEM;
const size_t mbedtls_kyle_cas_pem_len = sizeof(TEST_CA_CRT_RSA_SHA256_PEM);
const size_t mbedtls_kyle_svr_crt_len = sizeof(TEST_SVR_CRT_RSA_SHA256_PEM);
const size_t mbedtls_kyle_svr_key_len = sizeof(TEST_SVR_KEY_RSA_PEM);

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}

void *ssl_server(void *arg)
{
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_server";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&cache);
#endif
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 1. Seed the RNG
     */
    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Load the certificates and private RSA key
     */
    mbedtls_printf("\n  . Loading the server cert. and key...");
    fflush(stdout);

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_kyle_svr_crt,
                                 mbedtls_kyle_svr_crt_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_kyle_cas_pem,
                                 mbedtls_kyle_cas_pem_len);
    if (ret != 0) {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret =  mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_kyle_svr_key,
                                mbedtls_kyle_svr_key_len, NULL, 0,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 3. Setup the listening TCP socket
     */
    mbedtls_printf("  . Bind on https://localhost:4433/ ...");
    fflush(stdout);

    if ((ret = mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf("KYLE ============== \n\n");
        mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Setup stuff
     */
    mbedtls_printf("  . Setting up the SSL data....");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    /* force client authentication */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    /*
     * 5. Handshake
     */
    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 6. Read the HTTP Request
     */
    mbedtls_printf("  < Read from client:");
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf(" connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf(" connection was reset by peer\n");
                    break;

                default:
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", (unsigned int) -ret);
                    break;
            }

            break;
        }

        len = ret;
        mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);

        if (ret > 0) {
            break;
        }
    } while (1);

    /*
     * 7. Write the 200 Response
     */
    mbedtls_printf("  > Write to client:");
    fflush(stdout);

    len = sprintf((char *) buf, HTTP_RESPONSE,
                  mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n%s\n", len, (char *) buf);

    mbedtls_printf("  . Closing the connection...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
            ret != MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");
    fflush(stdout);

    ret = 0;
    goto reset;

exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&cache);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_psa_crypto_free();

    mbedtls_exit(ret);

    return 0;
}

int create_ssl_server(void) {
    sys_thread_t st = NULL;
    st = sys_thread_new("tls client server", ssl_server, NULL, 8192, 1);
    if (st == NULL)
    {
        return -1;
    }
    return 0;
}
