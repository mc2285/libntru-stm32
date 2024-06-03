//
//  rng.h
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#ifndef rng_h
#define rng_h

#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

#include "crypto_stream_salsa20.h"

extern char hal_sourced_random_seed[crypto_stream_salsa20_KEYBYTES];

int
_32_randombytes(unsigned char *x);

#endif /* rng_h */
