 segment .text
 global do_rdrand
 global do_rdseed

do_rdrand:
 xor    rax, rax
 rdrand rcx
 mov    [rdi], rcx
 setc   al
 ret

do_rdseed:
 xor    rax, rax
 rdseed rcx
 mov    [rdi], rcx
 setc   al
 ret
