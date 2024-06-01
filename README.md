## libntru-stm32

This library is a port of the official [libntru](https://github.com/jschanck/ntru) code
intended to be used on STM32 microcontrollers.

By porting I mean here removing everything but the core NTRU encryption and decryption functions and using
STM32H7 hardware cryptographic peripherals wherever possible and practical.
