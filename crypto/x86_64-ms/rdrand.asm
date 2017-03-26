 segment .text
 global do_rdrand
 global do_rdseed

do_rdrand:
 xor    rax, rax
 rdrand rdx
 mov    [rcx], rdx
 setc   al
 ret

do_rdseed:
 xor    rax, rax
 rdseed rdx
 mov    [rcx], rdx
 setc   al
 ret
