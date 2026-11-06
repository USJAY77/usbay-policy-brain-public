/* Read structured fields using OpenSSL's native RFC3161 decoder.
 * This helper does NOT verify signatures or grant authority. Its caller must
 * first verify the exact response bytes and bind this result to those bytes.
 * No private key, network, raw diagnostic output or custom ASN.1 parser.
 */
#include <openssl/ts.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LIMIT (2U * 1024U * 1024U)

static int number(const ASN1_INTEGER *value, int64_t maximum, int64_t *out) {
    if (value == NULL) { *out = 0; return 1; }
    if (ASN1_INTEGER_get_int64(out, value) != 1 || *out < 0 || *out > maximum)
        return 0;
    return 1;
}

int main(int argc, char **argv) {
    int result = 1;
    unsigned char *bytes = NULL;
    FILE *input = NULL, *output = NULL;
    TS_RESP *response = NULL;
    if (argc != 3) return 1;
    bytes = malloc(LIMIT + 1U);
    if (bytes == NULL || (input = fopen(argv[1], "rb")) == NULL) goto done;
    size_t size = fread(bytes, 1U, LIMIT + 1U, input);
    if (ferror(input) || size == 0U || size > LIMIT) goto done;
    const unsigned char *cursor = bytes;
    response = d2i_TS_RESP(NULL, &cursor, (long)size);
    if (response == NULL || cursor != bytes + size) goto done;
    TS_TST_INFO *info = TS_RESP_get_tst_info(response);
    if (info == NULL) goto done;
    const ASN1_GENERALIZEDTIME *time = TS_TST_INFO_get_time(info);
    TS_ACCURACY *accuracy = TS_TST_INFO_get_accuracy(info);
    if (time == NULL || accuracy == NULL) goto done;
    const ASN1_STRING *wire = (const ASN1_STRING *)time;
    const unsigned char *data = ASN1_STRING_get0_data(wire);
    /* Convert only the native, validated UTC field. Precision above six digits
     * fails closed; no human-readable OpenSSL diagnostic text is parsed.
     */
    int length = ASN1_STRING_length(wire);
    if (length < 15 || length > 22 || data == NULL || data[length-1] != 'Z') goto done;
    for (int i = 0; i < 14; i++) if (data[i] < '0' || data[i] > '9') goto done;
    if (length > 15) {
        if (length < 17 || data[14] != '.' || data[length-2] == '0') goto done;
        for (int i = 15; i < length-1; i++) if (data[i] < '0' || data[i] > '9') goto done;
    }
    struct tm parsed;
    memset(&parsed, 0, sizeof(parsed));
    if (ASN1_TIME_to_tm((const ASN1_TIME *)time, &parsed) != 1) goto done;
    const ASN1_INTEGER *seconds = TS_ACCURACY_get_seconds(accuracy);
    const ASN1_INTEGER *millis = TS_ACCURACY_get_millis(accuracy);
    const ASN1_INTEGER *micros = TS_ACCURACY_get_micros(accuracy);
    int64_t s, ms, us;
    if ((seconds == NULL && millis == NULL && micros == NULL) ||
        !number(seconds, 86400, &s) || !number(millis, 999, &ms) ||
        !number(micros, 999, &us) || (millis != NULL && ms == 0) ||
        (micros != NULL && us == 0)) goto done;
    output = fopen(argv[2], "wx");
    if (output == NULL) goto done;
    if (fprintf(output,
        "{\"schema\":1,\"generalized_time\":\"%.*s\",\"accuracy_us\":%lld}\n",
        length, (const char *)data, (long long)(s * 1000000 + ms * 1000 + us)) < 0)
        goto done;
    if (fflush(output) != 0) goto done;
    result = 0;
done:
    if (output != NULL && fclose(output) != 0) result = 1;
    if (input != NULL) fclose(input);
    TS_RESP_free(response);
    free(bytes);
    return result;
}
