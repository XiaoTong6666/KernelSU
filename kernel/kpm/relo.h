#ifndef _KP_RELO_H_
#define _KP_RELO_H_

#include <uapi/linux/elf.h>

struct kpm_module;

/* Keep KPM relocation entry points distinct from the kernel module loader hooks. */
int kpm_apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                           struct kpm_module *me);
int kpm_apply_relocate(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                       struct kpm_module *me);

#endif
