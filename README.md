# libntru-stm32

This library is an STM32 port of the official [pqntrusign](https://github.com/zhenfeizhang/pqntrusign-nist-submission) code
submitted to NIST.

By porting I mean here removing everything but the core signature generation and verification code, and adapting it to
STM32H7 hardware cryptographic peripherals wherever possible and practical.
