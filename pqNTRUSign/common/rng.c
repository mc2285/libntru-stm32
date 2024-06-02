//
//  rng.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include <string.h>
#include "rng.h"

int
randombytes(unsigned char *x, unsigned long long xlen)
{
    memcpy(x, "TODO: Implement randombytes() with HAL_RNG from STM32Cube", xlen);
    
    return RNG_SUCCESS;
}
