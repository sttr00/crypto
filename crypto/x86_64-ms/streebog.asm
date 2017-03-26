 segment .text
 global streebog_add_512_inplace_impl

streebog_add_512_inplace_impl:
; rcx = out
; rdx = in
 mov    rax, [rdx]
 add    [rcx], rax
 mov    rax, [rdx+8]
 adc    [rcx+8], rax
 mov    rax, [rdx+16]
 adc    [rcx+16], rax
 mov    rax, [rdx+24]
 adc    [rcx+24], rax
 mov    rax, [rdx+32]
 adc    [rcx+32], rax
 mov    rax, [rdx+40]
 adc    [rcx+40], rax
 mov    rax, [rdx+48]
 adc    [rcx+48], rax
 mov    rax, [rdx+56]
 adc    [rcx+56], rax
 ret
