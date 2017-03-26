 segment .text
 global _streebog_add_512_inplace_impl

_streebog_add_512_inplace_impl:
 mov    ecx, [esp+4] ; out
 mov    edx, [esp+8] ; in
 mov    eax, [edx]
 add    [ecx], eax
 mov    eax, [edx+4]
 adc    [ecx+4], eax
 mov    eax, [edx+8]
 adc    [ecx+8], eax
 mov    eax, [edx+12]
 adc    [ecx+12], eax
 mov    eax, [edx+16]
 adc    [ecx+16], eax
 mov    eax, [edx+20]
 adc    [ecx+20], eax
 mov    eax, [edx+24]
 adc    [ecx+24], eax
 mov    eax, [edx+28]
 adc    [ecx+28], eax
 mov    eax, [edx+32]
 adc    [ecx+32], eax
 mov    eax, [edx+36]
 adc    [ecx+36], eax
 mov    eax, [edx+40]
 adc    [ecx+40], eax
 mov    eax, [edx+44]
 adc    [ecx+44], eax
 mov    eax, [edx+48]
 adc    [ecx+48], eax
 mov    eax, [edx+52]
 adc    [ecx+52], eax
 mov    eax, [edx+56]
 adc    [ecx+56], eax
 mov    eax, [edx+60]
 adc    [ecx+60], eax
 ret
