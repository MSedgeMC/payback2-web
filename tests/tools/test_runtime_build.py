import importlib.util
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("build_runtime", ROOT / "tools/build_runtime.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)

# Synthetic C reproduces the interpreter's assertion-only declarations.
INTERPRETER = """
#include <assert.h>
#include <stdint.h>
#if defined(CONFIG_DEBUG_TCG)
# define tci_assert(cond) assert(cond)
#else
# define tci_assert(cond) ((void)0)
#endif
void execute(uint8_t *tb_ptr) {
#if defined(CONFIG_DEBUG_TCG) && !defined(NDEBUG)
    uint8_t op_size = tb_ptr[1];
    uint8_t *old_code_ptr = tb_ptr;
#endif
    tb_ptr += 2;
    tci_assert(tb_ptr == old_code_ptr + op_size);
}
"""


class RuntimeBuildTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "Native C syntax checker is unavailable")
    def test_assertions_compile_without_full_tcg_debug(self):
        source = BUILDER.enable_interpreter_assertions(INTERPRETER)
        for flags in ([], ["-DNDEBUG"]):
            with self.subTest(flags=flags):
                result = subprocess.run(["cc", "-std=c11", "-Werror", "-fsyntax-only", "-x", "c", *flags, "-"],
                                        input=source, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_upstream_guards_are_rejected(self):
        with self.assertRaises(ValueError):
            BUILDER.enable_interpreter_assertions(INTERPRETER.replace("CONFIG_DEBUG_TCG", "OTHER_GUARD"))


if __name__ == "__main__":
    unittest.main()
