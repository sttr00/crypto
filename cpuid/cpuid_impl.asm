 segment .text
 global _cpuid_impl

_cpuid_impl:
 push  ebx
 push  esi
 mov   esi, [esp+12]
 mov   eax, [esp+16]
 mov   ecx, [esp+20]
 cpuid
 mov   [esi], eax
 mov   [esi+4], ebx
 mov   [esi+8], ecx
 mov   [esi+12], edx
 pop   esi
 pop   ebx
 ret
