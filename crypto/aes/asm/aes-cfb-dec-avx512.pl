#! /usr/bin/env perl
# Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
# Copyright (c) 2025, Intel Corporation. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# Implements AES-CFB128 decryption with Intel VAES

$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

$code="";

$code.=<<___;
.text

immediate_value1:
    .quad 0x0000000000000000  #
    .quad 0x1111111111111111  # Upper 64 bits
immediate_value2:
    .quad 0x2222222222222222  #
    .quad 0x3333333333333333  # Upper 64 bits
immediate_value3:
    .quad 0x4444444444444444  #
    .quad 0x5555555555555555  # Upper 64 bits
immediate_value4:
    .quad 0x6666666666666666  #
    .quad 0x7777777777777777  # Upper 64 bits
immediate_value5:
    .quad 0x8888888888888888  #
    .quad 0x9999999999999999  # Upper 64 bits
___


#################################################################
# Signature:
#
# void aes_cfb128_vaes_dec(
#     const unsigned char *in,
#     unsigned char *out,
#     size_t len,
#     const AES_KEY *ks,
#     const unsigned char ivec[16],
#     /*in-out*/ int *num);
#
# Preconditions:
# - all pointers are valid (not NULL...)
# - AES key schedule and rounds in `ks` are precomputed
#
# Invariants:
# - `*num` is between 0 and 15
#################################################################

$code.=<<___;
.globl  aes_cfb128_vaes_dec
.type   aes_cfb128_vaes_dec,\@function,6
.align  16
aes_cfb128_vaes_dec:
.cfi_startproc
    endbranch
___

$inp="%rdi";          # arg0
$out="%rsi";          # arg1
$len="%rdx";          # arg2

$key_original="%rcx"; # arg3
$key_backup="%r10";
$key_crt="%r10";

$ivp="%r8";           # arg4
$nump="%r9";          # arg5

$idx="%r11";
$left="%rcx";
$mask="%rax";

$rounds="%r11d";

$rnd0key="%xmm0";
$rnd0key_zmm="%zmm0";

$rndNkey="%xmm1";
$rndNkey_zmm="%zmm1";

$temp="%xmm2";
$temp_zmm="%zmm2";

$cipher="%xmm3";
$cipher_zmm="%zmm3";

$code.=<<___;

    movsl ($nump),$idx               # nump points to the byte index in the first partial block
                                     # $idx belongs to 0..15; non-zero means a partial first block

    test $len,$len                   # return early if $len==0
    jz .Laes_cfb128_vaes_dec

    test $idx,$idx                   # check if the first block is partial
    jz .Laes_cfb128_dec_mid

###########################################################
# first partial block processing
###########################################################

    mov $key_original,$key_backup    # make room for variable shl with cl

    mov \$0x10,$left                 # first block is partial
    sub $idx,$left                   # calculate how many bytes $left to process in the block
    cmp $len,$left                   #
    cmova $len,$left                 # $left = min(16-$idx,$len)

    mov \$1,$mask                    # build a mask with the least significant $left bits set
    shlq %cl,$mask                   # $left is left shift counter
    dec $mask                        # $mask is 2^$left-1
    kmovq $mask,%k1

    mov $idx,%rax                    # keep in-out num in %al
    add $left,%rax                   # advance num
    and \$0x0F,%al                   # wrap-around in a 16-byte block

    leaq ($idx,$ivp),%r11            # process $left iv bytes
    vmovdqu8 (%r11),%xmm0
    vmovdqu8 ($inp),%xmm1            # process $left input bytes
    vpxor %xmm0,%xmm1,%xmm2          # CipherFeedBack XOR
    vmovdqu8 %xmm2,($out){%k1}       # write $left output bytes
    vmovdqu8 %xmm1,(%r11){%k1}       # blend $left input bytes into iv

    add $left,$inp                   # advance pointers
    add $left,$out
    sub $left,$len
    jz .Laes_cfb128_dec_end          # return early if no AES encryption required

    mov $key_backup,$key_original    # restore "key_original" as arg3

.Laes_cfb128_dec_mid:

###########################################################
# inner full blocks processing
###########################################################

    vmovdqu ($ivp),$temp             # load iv

    cmp \$0x40,$len                  # any full MB4 ciphertext blocks left ?
    jb .Laes_cfb128_dec_check_10

###################
# mb4
###################

    mov \$0b11111100, %eax
    kmovw %eax, %k2

.Loop_aes_cfb128_dec_main_loop_mb4:
    sub \$0x40,$len

    mov $key_original,$key_crt
    mov 240($key_crt),$rounds        # load AES rounds
                                     # 240 is the byte-offset of the rounds field in AES_KEY


# vmovdqu32 _mm512_loadu_si512

    vmovdqu32 ($inp),$cipher_zmm       # load ciphertext block

    vshufi64x2 \$0b10010011,$cipher_zmm,$cipher_zmm,$temp_zmm {%k2} 

    lea 64($inp),$inp                # inp points to next ciphertext

    vbroadcasti32x4 ($key_crt),$rnd0key_zmm   # load round 0 key
    vbroadcasti32x4 16($key_crt),$rndNkey_zmm # load round 1 key

    lea 32($key_crt),$key_crt              # key points to the 2nd round key
    vpxord $rnd0key_zmm,$temp_zmm,$temp_zmm          # pre-whitening
.Loop_aesenc_mb4:
    vaesenc $rndNkey_zmm,$temp_zmm,$temp_zmm            # encrypt with current round key
    dec $rounds

    vbroadcasti32x4 ($key_crt),$rndNkey_zmm   # load next round key
    
    lea 16($key_crt),$key_crt        # key points to the next round key
    jnz .Loop_aesenc_mb4             # process all encryption rounds but the last

    vaesenclast $rndNkey_zmm,$temp_zmm,$temp_zmm        # encrypt with the last round key

    vpxord $cipher_zmm,$temp_zmm,$temp_zmm              # CipherFeedBack XOR
    cmp \$0x40,$len
    vmovdqu32 $temp_zmm,($out)             # write plaintext
    vmovdqu8 $cipher_zmm,$temp_zmm
    lea 64($out),$out                # out points to the next output block

    vextracti64x2 \$3,$temp_zmm,$temp

    jge .Loop_aes_cfb128_dec_main_loop_mb4

    xor %eax,%eax                    # reset num when processing full blocks

    vmovdqu $temp,($ivp)             # latest plaintext block is next dencryption input









.Laes_cfb128_dec_check_10:
    cmp \$0x10,$len                  # any full ciphertext blocks left ?
    jb .Laes_cfb128_dec_post

###################
# mb1
###################

.Loop_aes_cfb128_dec_main_loop_mb1:
    sub \$0x10,$len

    mov $key_original,$key_crt
    mov 240($key_crt),$rounds        # load AES rounds
                                     # 240 is the byte-offset of the rounds field in AES_KEY

    vmovdqu ($inp),$cipher           # load ciphertext block
    lea 16($inp),$inp                # inp points to next ciphertext

    vmovdqu ($key_crt),$rnd0key      # load round 0 key
    vmovdqu 16($key_crt),$rndNkey    # load round 1 key
    lea 32($key_crt),$key_crt        # key points to the 2nd round key
    vpxor $rnd0key,$temp,$temp             # pre-whitening
.Loop_aesenc_mb1:
    aesenc $rndNkey,$temp            # encrypt with current round key
    dec $rounds
    vmovdqu ($key_crt),$rndNkey      # load next round key
    lea 16($key_crt),$key_crt        # key points to the next round key
    jnz .Loop_aesenc_mb1                 # process all encryption rounds but the last

    aesenclast $rndNkey,$temp        # encrypt with the last round key

    vpxor $cipher,$temp,$temp              # CipherFeedBack XOR
    cmp \$0x10,$len
    vmovdqu $temp,($out)             # write plaintext
    vmovdqu8 $cipher,$temp
    lea 16($out),$out                # out points to the next output block
    jge .Loop_aes_cfb128_dec_main_loop_mb1

    xor %eax,%eax                    # reset num when processing full blocks

    vmovdqu $temp,($ivp)             # latest plaintext block is next dencryption input

.Laes_cfb128_dec_post:

###########################################################
# last partial block processing
###########################################################

    test $len,$len
    jz .Laes_cfb128_dec_end

    mov $key_original,$key_crt
    mov 240($key_crt),$rounds        # load AES rounds
                                     # 240 is the byte-offset of the rounds field in AES_KEY

    vmovdqu ($key_crt),$rnd0key      # load round 0 key
    vmovdqu 16($key_crt),$rndNkey    # load round 1 key
    lea 32($key_crt),$key_crt        # key points to the 2nd round key
    vpxor $rnd0key,$temp,$temp             # pre-whitening

.Loop_aesenc2:
    aesenc $rndNkey,$temp            # encrypt with current round key
    dec $rounds
    vmovdqu ($key_crt),$rndNkey      # load next round key
    lea 16($key_crt),$key_crt        # key points to the next round key
    jnz .Loop_aesenc2                # process all encryption rounds but the last

    aesenclast $rndNkey,$temp        # encrypt with the last round key

    mov $len,%rax                    # num=$len
    mov \$1,%r11                     # build a mask with the least significant $len bits set
    mov %dl,%cl                      # $len is left shift counter less than 16
    shlq %cl,%r11
    dec %r11                         # mask is 2^$len-1
    kmovq %r11,%k1

    vmovdqu8 ($inp),%xmm1{%k1}{z}    # read $len input bytes
    vpxor $temp,%xmm1,%xmm0         # CipherFeedBack XOR
    vmovdqu8 %xmm0,($out){%k1}       # write $len output bytes
    vpblendmb %xmm1,$temp,$temp {%k1} # blend $len input bytes into iv 

    vmovdqu8 $temp,($ivp)            # write $len chained/streaming input bytes

.Laes_cfb128_dec_end:

    mov %eax,($nump)                 # num is in/out, update for future/chained calls

    vpxor $rnd0key,$rnd0key,$rnd0key # zeroize
    vpxor $rndNkey,$rndNkey,$rndNkey # zeroize
    vpxord $cipher_zmm,$cipher_zmm,$cipher_zmm    # zeroize
    vpxord $temp_zmm,$temp_zmm,$temp_zmm          # zeroize

.Laes_cfb128_vaes_dec:
    vzeroupper
    ret
.cfi_endproc
.size aes_cfb128_vaes_dec,.-aes_cfb128_vaes_dec
___

print $code;

close STDOUT or die "error closing STDOUT: $!";
