 segment .text
 global _do_rdrand
 global _do_rdseed

_do_rdrand:
 mov    edx, [esp+4]
 xor    eax, eax
 rdrand ecx
 mov    [edx], ecx
 setc   al
 ret

_do_rdseed:
 mov    edx, [esp+4]
 xor    eax, eax
 rdseed ecx
 mov    [edx], ecx
 setc   al
 ret
