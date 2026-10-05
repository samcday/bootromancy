@ bn_from_bytes.s — reconstruction of ROM 0x4554..0x45FF (172 bytes, 43 words).
@ bytes(ptr r0, len r1) -> bignum handle. Linked at 0x04554; the branch and
@ call to out-of-function targets (alloc 0x4ab8, byte accessor 0x24dc) are
@ hand-encoded .word emissions so their fields match the ROM bit-for-bit.
    .arm
    .text
    .globl bn_from_bytes
bn_from_bytes:
    push    {r4, r5, r6, r7, r8, r9, r10, lr}
    subs    r4, r1, #0
    mov     r9, r0
    mov     r5, #0
    pople   {r4, r5, r6, r7, r8, r9, r10, lr}
    movle   r0, #1
    movle   r1, #0
    .word   0xDA000150          @ ble +0x150 -> 0x4ab8 (alloc immediate path)
    sub     r0, r4, #1
    asr     r1, r0, #0x1f
    add     r1, r0, r1, lsr #30
    mov     r0, #1
    add     r6, r0, r1, asr #2
    subs    r12, r6, #0x100
    bic     r1, r1, #3
    sub     r0, r4, #1
    .word   0xA25CC001          @ subsge ip, ip, #1
    sub     r7, r0, r1
    bgt     return_zero
    mov     r1, #0
    mov     r0, #1
    .word   0xEB000142          @ bl 0x4ab8
    movs    r8, r0
    strne   r6, [r8, #0x404]
    bne     limbloop_entry
return_zero:
    mov     r0, #0
    pop     {r4, r5, r6, r7, r8, r9, r10, lr}
    bx      lr
byte_loop:
    mov     r0, r9
    .word   0xEBFFF7C3          @ bl 0x24dc
    sub     r7, r7, #1
    cmn     r7, #1
    subeq   r6, r6, #1
    orr     r5, r0, r5, lsl #8
    streq   r5, [r8, r6, lsl #2]
    moveq   r5, #0
    moveq   r7, #3
    add     r9, r9, #1
limbloop_entry:
    subs    r0, r4, #0
    sub     r4, r4, #1
    bgt     byte_loop
    mov     r0, r8
    .word   0xEAFFFFEE          @ b return_zero
