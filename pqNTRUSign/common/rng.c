//
//  rng.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include <string.h>
#include "rng.h"

#include "crypto_stream_salsa20.h"

int _32_randombytes(unsigned char *x)
{
    memcpy(x, hal_sourced_random_seed, crypto_stream_salsa20_KEYBYTES);
    
    return RNG_SUCCESS;
}
