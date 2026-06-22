#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import argparse


PROFILES = {
    "x86_6_12": {
        "syscall32_style": "double_undef",
        "syscallx32_style": "noreturn",
        "cpufeatures_style": "feature_exit_to_user",
        "drivers_cpu_style": "root_attrs_vmscape",
        "cpu_h_style": "has_indirect_target",
    },
    "x86_6_6": {
        "syscall32_style": "single_undef",
        "syscallx32_style": "plain",
        "cpufeatures_style": "bug_ibpb_no_ret",
        "drivers_cpu_style": "vuln_macro",
        "cpu_h_style": "no_indirect_target",
    },
    "x86_5_15": {
        "syscall32_style": "single_undef",
        "syscallx32_style": "plain",
        "cpufeatures_style": "bug_ibpb_no_ret",
        "drivers_cpu_style": "vuln_explicit",
        "cpu_h_style": "no_indirect_target",
    },
    "x86_6_1": {
        "syscall32_style": "single_undef",
        "syscallx32_style": "plain",
        "cpufeatures_style": "bug_ibpb_no_ret",
        "drivers_cpu_style": "vuln_explicit",
        "cpu_h_style": "no_indirect_target",
    },
    "x86_6_1_legacy_direct": {
        "syscall32_style": "table_defined",
        "syscallx32_style": "table_defined",
        "cpufeatures_style": "legacy_bug_word",
        "drivers_cpu_style": "vuln_legacy",
        "cpu_h_style": "no_indirect_target",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--common-dir", required=True)
    parser.add_argument("--branch", required=True)
    return parser.parse_args()


class Mutator:
    def __init__(self, common_dir: Path, branch: str):
        self.common = common_dir
        self.branch = branch

    def log(self, path_str: str, status: str, detail: str) -> None:
        print(f"[{status}] {path_str}: {detail}")

    def read_text(self, path_str: str) -> str:
        return (self.common / path_str).read_text()

    def write_text(self, path_str: str, data: str) -> None:
        (self.common / path_str).write_text(data)

    def replace_once(self, path_str: str, old_line: str, new_block: str) -> None:
        data = self.read_text(path_str)
        if new_block in data:
            self.log(path_str, "already present", "replacement block already exists")
            return
        if old_line not in data:
            self.log(path_str, "anchor not found", repr(old_line.strip()))
            raise SystemExit(f"Failed to locate replacement anchor in {path_str}")
        self.write_text(path_str, data.replace(old_line, new_block, 1))
        self.log(path_str, "patched", repr(old_line.strip()))

    def insert_after(self, path_str: str, anchor: str, addition: str) -> None:
        data = self.read_text(path_str)
        if addition in data:
            self.log(path_str, "already present", "insertion block already exists")
            return
        if anchor not in data:
            self.log(path_str, "anchor not found", repr(anchor.strip()))
            raise SystemExit(f"Failed to locate insertion anchor in {path_str}")
        self.write_text(path_str, data.replace(anchor, anchor + addition, 1))
        self.log(path_str, "patched", repr(anchor.strip()))

    def insert_after_function(self, path_str: str, signature: str, function_end: str, addition: str) -> None:
        data = self.read_text(path_str)
        if addition in data:
            self.log(path_str, "already present", "function insertion block already exists")
            return
        start = data.find(signature)
        if start == -1:
            self.log(path_str, "anchor not found", repr(signature.strip()))
            raise SystemExit(f"Failed to locate function signature anchor in {path_str}")
        end = data.find(function_end, start)
        if end == -1:
            self.log(path_str, "anchor not found", repr(function_end.strip()))
            raise SystemExit(f"Failed to locate function end anchor in {path_str}")
        end += len(function_end)
        self.write_text(path_str, data[:end] + addition + data[end:])
        self.log(path_str, "patched", repr(signature.strip()))

    def insert_before_in_block(self, path_str: str, block_start: str, before: str, addition: str) -> None:
        data = self.read_text(path_str)
        if addition in data:
            self.log(path_str, "already present", "block insertion already exists")
            return
        start = data.find(block_start)
        if start == -1:
            self.log(path_str, "anchor not found", repr(block_start.strip()))
            raise SystemExit(f"Failed to locate block start anchor in {path_str}")
        pos = data.find(before, start)
        if pos == -1:
            self.log(path_str, "anchor not found", repr(before.strip()))
            raise SystemExit(f"Failed to locate block insertion anchor in {path_str}")
        self.write_text(path_str, data[:pos] + addition + data[pos:])
        self.log(path_str, "patched", repr(block_start.strip()))

    def detect_layout(self) -> dict[str, str]:
        drivers_cpu = self.read_text("drivers/base/cpu.c")
        cpufeatures = self.read_text("arch/x86/include/asm/cpufeatures.h")
        cpu_h = self.read_text("include/linux/cpu.h")
        syscall_x32 = self.read_text("arch/x86/entry/syscall_x32.c")
        syscall_32 = self.read_text("arch/x86/entry/syscall_32.c")

        if "ia32_sys_call_table[] = {" in syscall_32:
            syscall32_style = "table_defined"
        elif "#undef  __SYSCALL\n#endif\n" in syscall_32:
            syscall32_style = "double_undef"
        elif "#undef __SYSCALL\n#endif\n" in syscall_32:
            syscall32_style = "single_undef"
        else:
            syscall32_style = "unknown"

        if "x32_sys_call_table[] = {" in syscall_x32:
            syscallx32_style = "table_defined"
        elif "__SYSCALL_NORETURN" in syscall_x32:
            syscallx32_style = "noreturn"
        else:
            syscallx32_style = "plain"

        if "X86_FEATURE_IBPB_EXIT_TO_USER" in cpufeatures:
            cpufeatures_style = "feature_exit_to_user"
        elif "X86_BUG_IBPB_NO_RET" in cpufeatures:
            cpufeatures_style = "bug_ibpb_no_ret"
        elif "#define X86_BUG(x)\t\t\t(NCAPINTS*32 + (x))" in cpufeatures:
            cpufeatures_style = "legacy_bug_word"
        else:
            cpufeatures_style = "unknown"

        if "cpu_root_attrs[]" in drivers_cpu and "CPU_SHOW_VULN_FALLBACK(vmscape);" in drivers_cpu:
            drivers_cpu_style = "root_attrs_vmscape"
        elif "cpu_root_vulnerabilities_attrs[]" in drivers_cpu and "CPU_SHOW_VULN_FALLBACK(reg_file_data_sampling);" in drivers_cpu:
            drivers_cpu_style = "vuln_macro"
        elif "cpu_root_vulnerabilities_attrs[]" in drivers_cpu and "ssize_t __weak cpu_show_reg_file_data_sampling" in drivers_cpu:
            drivers_cpu_style = "vuln_explicit"
        elif "cpu_root_vulnerabilities_attrs[]" in drivers_cpu and "static DEVICE_ATTR(retbleed, 0444, cpu_show_retbleed, NULL);" in drivers_cpu:
            drivers_cpu_style = "vuln_legacy"
        else:
            drivers_cpu_style = "unknown"

        cpu_h_style = "has_indirect_target" if "cpu_show_indirect_target_selection" in cpu_h else "no_indirect_target"
        return {
            "syscall32_style": syscall32_style,
            "syscallx32_style": syscallx32_style,
            "cpufeatures_style": cpufeatures_style,
            "drivers_cpu_style": drivers_cpu_style,
            "cpu_h_style": cpu_h_style,
        }

    def score_profile(self, profile_name: str, features: dict[str, str]) -> tuple[int, int, int]:
        expected = PROFILES[profile_name]
        score = 0
        max_score = 0
        for key, expected_value in expected.items():
            max_score += 1
            if features.get(key) == expected_value:
                score += 1

        branch_bonus = 0
        if self.branch.startswith("common-android16-6.12") and profile_name == "x86_6_12":
            branch_bonus = 1
        elif self.branch.startswith("common-android15-6.6") and profile_name == "x86_6_6":
            branch_bonus = 1
        elif self.branch.startswith("common-android13-5.15") and profile_name == "x86_5_15":
            branch_bonus = 1
        elif self.branch.startswith("common-android14-6.1") and profile_name == "x86_6_1":
            branch_bonus = 1
        elif self.branch.startswith("common-android14-6.1") and profile_name == "x86_6_1_legacy_direct":
            branch_bonus = 1
        return score, max_score, branch_bonus

    def select_profile(self, features: dict[str, str]) -> str | None:
        print("Detected x86 layout features:")
        for key, value in features.items():
            print(f"  {key}: {value}")

        results = {name: self.score_profile(name, features) for name in PROFILES}
        print("Profile scores:")
        for profile_name, (score, max_score, branch_bonus) in results.items():
            print(f"  {profile_name}: score={score}/{max_score}, branch_bonus={branch_bonus}")

        best_name = max(results, key=lambda name: (results[name][0], results[name][2]))
        best_score, _best_max, _ = results[best_name]
        if best_score < 4:
            print(f"No profile passed threshold for branch {self.branch}; skipping hardening patch")
            return None
        print(f"Selected x86 layout profile: {best_name}")
        return best_name

    def patch_entry_common(self) -> None:
        self.replace_once(
            "arch/x86/entry/common.c",
            "\t\tregs->ax = x64_sys_call(regs, unr);\n",
            """\t\tif (likely(cpu_feature_enabled(X86_FEATURE_INDIRECT_SAFE) &&\n\t\t\t   x86_syscall_hardening_enabled))\n\t\t\tregs->ax = sys_call_table[unr](regs);\n\t\telse\n\t\t\tregs->ax = x64_sys_call(regs, unr);\n""",
        )
        self.replace_once(
            "arch/x86/entry/common.c",
            "\t\tregs->ax = x32_sys_call(regs, xnr);\n",
            """\t\tif (likely(cpu_feature_enabled(X86_FEATURE_INDIRECT_SAFE) &&\n\t\t\t   x86_syscall_hardening_enabled))\n\t\t\tregs->ax = x32_sys_call_table[xnr](regs);\n\t\telse\n\t\t\tregs->ax = x32_sys_call(regs, xnr);\n""",
        )
        self.replace_once(
            "arch/x86/entry/common.c",
            "\t\tregs->ax = ia32_sys_call(regs, unr);\n",
            """\t#ifdef CONFIG_X86_64\n\t\tif (likely(cpu_feature_enabled(X86_FEATURE_INDIRECT_SAFE) &&\n\t\t\t   x86_syscall_hardening_enabled))\n\t\t\tregs->ax = ia32_sys_call_table[unr](regs);\n\t\telse\n\t#endif\n\t\t\tregs->ax = ia32_sys_call(regs, unr);\n""",
        )

    def patch_syscall_32_612(self) -> None:
        self.insert_after(
            "arch/x86/entry/syscall_32.c",
            "#undef  __SYSCALL\n#endif\n",
            """\n#ifdef CONFIG_IA32_EMULATION\n#define __SYSCALL(nr, sym) __ia32_##sym,\nconst sys_call_ptr_t ia32_sys_call_table[] = {\n#include <asm/syscalls_32.h>\n};\n#undef __SYSCALL\n#endif\n""",
        )

    def patch_syscall_32_61(self) -> None:
        self.insert_after(
            "arch/x86/entry/syscall_32.c",
            "#undef __SYSCALL\n#endif\n",
            """\n#ifdef CONFIG_IA32_EMULATION\n#define __SYSCALL(nr, sym) __ia32_##sym,\nconst sys_call_ptr_t ia32_sys_call_table[] = {\n#include <asm/syscalls_32.h>\n};\n#undef __SYSCALL\n#endif\n""",
        )

    def patch_syscall_x32_612(self) -> None:
        self.insert_after(
            "arch/x86/entry/syscall_x32.c",
            "#define __SYSCALL_NORETURN __SYSCALL\n",
            """\n#define __SYSCALL(nr, sym) __x64_##sym,\nconst sys_call_ptr_t x32_sys_call_table[] = {\n#include <asm/syscalls_x32.h>\n};\n#undef __SYSCALL\n""",
        )

    def patch_syscall_x32_61(self) -> None:
        self.insert_after(
            "arch/x86/entry/syscall_x32.c",
            "#undef __SYSCALL\n",
            """\n#define __SYSCALL(nr, sym) __x64_##sym,\nconst sys_call_ptr_t x32_sys_call_table[] = {\n#include <asm/syscalls_x32.h>\n};\n#undef __SYSCALL\n""",
        )

    def patch_cpufeatures_612(self) -> None:
        self.insert_after(
            "arch/x86/include/asm/cpufeatures.h",
            "#define X86_FEATURE_IBPB_EXIT_TO_USER  (21*32+14) /* Use IBPB on exit-to-userspace, see VMSCAPE bug */\n",
            "#define X86_FEATURE_INDIRECT_SAFE      (21*32+15) /* Indirect syscall dispatch is hardened */\n",
        )

    def patch_cpufeatures_61(self) -> None:
        self.insert_after(
            "arch/x86/include/asm/cpufeatures.h",
            "#define X86_FEATURE_CLEAR_BHB_LOOP_ON_VMEXIT (21*32+ 4) /* \"\" Clear branch history at vmexit using SW loop */\n",
            "#define X86_FEATURE_INDIRECT_SAFE\t(21*32+15) /* Indirect syscall dispatch is hardened */\n",
        )

    def patch_syscall_h(self) -> None:
        self.insert_after(
            "arch/x86/include/asm/syscall.h",
            "extern const sys_call_ptr_t sys_call_table[];\n",
            """\n#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)\nextern const sys_call_ptr_t ia32_sys_call_table[];\n#endif\n\nextern const sys_call_ptr_t x32_sys_call_table[];\n\n#ifdef CONFIG_X86_64\nextern bool x86_syscall_hardening_enabled;\n#endif\n""",
        )

    def patch_cpu_common_insert_block(self) -> None:
        self.insert_after(
            "arch/x86/kernel/cpu/common.c",
            "early_param(\"noinvpcid\", x86_noinvpcid_setup);\n",
            """\n#ifdef CONFIG_X86_64\nbool x86_syscall_hardening_enabled __ro_after_init = true;\n\nstatic int __init x86_syscall_hardening_setup(char *str)\n{\n\tif (!str)\n\t\treturn -EINVAL;\n\n\tif (!strcmp(str, \"off\")) {\n\t\tx86_syscall_hardening_enabled = false;\n\t\tpr_info(\"syscall_hardening: indirect syscall dispatch disabled\\n\");\n\t\treturn 0;\n\t}\n\n\tif (!strcmp(str, \"on\"))\n\t\treturn 0;\n\n\treturn -EINVAL;\n}\nearly_param(\"syscall_hardening\", x86_syscall_hardening_setup);\n\nssize_t cpu_show_syscall_hardening(struct device *dev,\n\t\t\t\t   struct device_attribute *attr,\n\t\t\t\t   char *buf)\n{\n\treturn sysfs_emit(buf, \"%s\\n\",\n\t\t\tx86_syscall_hardening_enabled ? \"on\" : \"off\");\n}\n#endif\n""",
        )

    def patch_cpu_common_finalize(self) -> None:
        self.replace_once(
            "arch/x86/kernel/cpu/common.c",
            "\tcpu_select_mitigations();\n",
            "\tsetup_force_cpu_cap(X86_FEATURE_INDIRECT_SAFE);\n\tcpu_select_mitigations();\n",
        )

    def patch_drivers_cpu_612(self) -> None:
        self.insert_after(
            "drivers/base/cpu.c",
            "#ifdef CONFIG_GENERIC_CPU_AUTOPROBE\nstatic DEVICE_ATTR(modalias, 0444, print_cpu_modalias, NULL);\n#endif\n",
            "static DEVICE_ATTR(syscall_hardening, 0444, cpu_show_syscall_hardening, NULL);\n",
        )
        self.insert_before_in_block(
            "drivers/base/cpu.c",
            "CPU_SHOW_VULN_FALLBACK(vmscape);\n\n",
            "static DEVICE_ATTR(meltdown, 0444, cpu_show_meltdown, NULL);\n",
            """ssize_t __weak cpu_show_syscall_hardening(struct device *dev,\n\t\t\t\t  struct device_attribute *attr,\n\t\t\t\t  char *buf)\n{\n\treturn sysfs_emit(buf, \"unknown\\n\");\n}\n""",
        )
        self.insert_before_in_block(
            "drivers/base/cpu.c",
            "static struct attribute *cpu_root_attrs[] = {\n",
            "\tNULL\n};\n",
            "\t&dev_attr_syscall_hardening.attr,\n",
        )

    def patch_drivers_cpu_61(self) -> None:
        self.insert_after_function(
            "drivers/base/cpu.c",
            "ssize_t __weak cpu_show_reg_file_data_sampling(struct device *dev,\n",
            "\treturn sysfs_emit(buf, \"Not affected\\n\");\n}\n",
            """\nssize_t __weak cpu_show_syscall_hardening(struct device *dev,\n\t\t\t\t\t  struct device_attribute *attr,\n\t\t\t\t\t  char *buf)\n{\n\treturn sysfs_emit(buf, \"unknown\\n\");\n}\n""",
        )
        self.insert_after(
            "drivers/base/cpu.c",
            "static DEVICE_ATTR(reg_file_data_sampling, 0444, cpu_show_reg_file_data_sampling, NULL);\n",
            "static DEVICE_ATTR(syscall_hardening, 0444, cpu_show_syscall_hardening, NULL);\n",
        )
        self.insert_after(
            "drivers/base/cpu.c",
            "\t&dev_attr_reg_file_data_sampling.attr,\n",
            "\t&dev_attr_syscall_hardening.attr,\n",
        )

    def patch_drivers_cpu_66(self) -> None:
        self.insert_after(
            "drivers/base/cpu.c",
            "CPU_SHOW_VULN_FALLBACK(reg_file_data_sampling);\n",
            """ssize_t __weak cpu_show_syscall_hardening(struct device *dev,\n\t\t\t\t\t  struct device_attribute *attr,\n\t\t\t\t\t  char *buf)\n{\n\treturn sysfs_emit(buf, \"unknown\\n\");\n}\n""",
        )
        self.insert_after(
            "drivers/base/cpu.c",
            "static DEVICE_ATTR(reg_file_data_sampling, 0444, cpu_show_reg_file_data_sampling, NULL);\n",
            "static DEVICE_ATTR(syscall_hardening, 0444, cpu_show_syscall_hardening, NULL);\n",
        )
        self.insert_before_in_block(
            "drivers/base/cpu.c",
            "static struct attribute *cpu_root_vulnerabilities_attrs[] = {\n",
            "\tNULL\n};\n",
            "\t&dev_attr_syscall_hardening.attr,\n",
        )

    def patch_cpu_h(self) -> None:
        self.insert_after(
            "include/linux/cpu.h",
            "extern ssize_t cpu_show_reg_file_data_sampling(struct device *dev,\n\t\t\t\t\t       struct device_attribute *attr, char *buf);\n",
            """extern ssize_t cpu_show_syscall_hardening(struct device *dev,\n\t\t\t\t\t  struct device_attribute *attr,\n\t\t\t\t\t  char *buf);\n""",
        )

    def mark_legacy_direct_layout(self) -> None:
        self.log("arch/x86/entry/common.c", "already present", "direct syscall table dispatch already exists")
        self.log("arch/x86/entry/syscall_32.c", "already present", "ia32 syscall table already exists")
        self.log("arch/x86/entry/syscall_x32.c", "already present", "x32 syscall table already exists")
        self.log("arch/x86/include/asm/syscall.h", "already present", "ia32/x32 syscall table declarations already exist")

    def apply(self) -> str | None:
        features = self.detect_layout()
        selected_profile = self.select_profile(features)

        if selected_profile is None:
            return None

        if selected_profile == "x86_6_1_legacy_direct":
            self.mark_legacy_direct_layout()
            return selected_profile

        self.patch_entry_common()

        if features["syscall32_style"] == "double_undef":
            self.patch_syscall_32_612()
        elif features["syscall32_style"] == "single_undef":
            self.patch_syscall_32_61()

        if features["syscallx32_style"] == "noreturn":
            self.patch_syscall_x32_612()
        elif features["syscallx32_style"] == "plain":
            self.patch_syscall_x32_61()

        if features["cpufeatures_style"] == "feature_exit_to_user":
            self.patch_cpufeatures_612()
        elif features["cpufeatures_style"] == "bug_ibpb_no_ret":
            self.patch_cpufeatures_61()

        self.patch_syscall_h()
        self.patch_cpu_common_insert_block()
        self.patch_cpu_common_finalize()

        if features["drivers_cpu_style"] == "root_attrs_vmscape":
            self.patch_drivers_cpu_612()
        elif features["drivers_cpu_style"] == "vuln_macro":
            self.patch_drivers_cpu_66()
        elif features["drivers_cpu_style"] == "vuln_explicit":
            self.patch_drivers_cpu_61()

        self.patch_cpu_h()
        return selected_profile


def main() -> None:
    args = parse_args()
    mutator = Mutator(Path(args.common_dir), args.branch)
    selected_profile = mutator.apply()
    if selected_profile is None:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
