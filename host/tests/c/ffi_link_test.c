/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 Taktflow Systems */

#include "score/crypto/hsm.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    uint8_t random_bytes[32] = {0};

    assert(HSM_Init() == HSM_OK);
    assert(HSM_Random(random_bytes, sizeof(random_bytes)) == HSM_OK);
    assert(HSM_Deinit() == HSM_OK);

    printf("%02x%02x%02x%02x\n",
           random_bytes[0],
           random_bytes[1],
           random_bytes[2],
           random_bytes[3]);
    return 0;
}
