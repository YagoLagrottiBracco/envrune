import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import envrune  # noqa: E402


def fake_envrune(body: str) -> str:
    """A stand-in for the envrune CLI, as a shell script."""
    directory = tempfile.mkdtemp(prefix="envrune-python-")
    path = os.path.join(directory, "envrune")
    with open(path, "w") as script:
        script.write("#!/bin/sh\n" + body + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


@unittest.skipIf(os.name == "nt", "the fake envrune is a shell script")
class LoadTest(unittest.TestCase):
    def tearDown(self):
        for name in ("ENVRUNE_T_A", "ENVRUNE_T_B"):
            os.environ.pop(name, None)

    def test_sets_variables_and_keeps_ones_already_set(self):
        binary = fake_envrune("""printf '%s\\n' '{"ENVRUNE_T_A": "from vault", "ENVRUNE_T_B": "x\\ny"}'""")
        os.environ["ENVRUNE_T_A"] = "already set"
        values = envrune.load(binary=binary)
        self.assertEqual(values["ENVRUNE_T_A"], "from vault")
        self.assertEqual(os.environ["ENVRUNE_T_A"], "already set")
        self.assertEqual(os.environ["ENVRUNE_T_B"], "x\ny")
        envrune.load(binary=binary, override=True)
        self.assertEqual(os.environ["ENVRUNE_T_A"], "from vault")

    def test_passes_the_environment_and_never_prompts(self):
        binary = fake_envrune("""[ "$*" = "env --format json --no-prompt --env staging" ] || exit 9; echo '{}'""")
        self.assertEqual(envrune.load("staging", binary=binary), {})

    def test_locked_vault_is_an_error_with_envrunes_message(self):
        binary = fake_envrune("""echo '[ERROR] The vault is locked. Run `envrune unlock` first.' >&2; exit 1""")
        with self.assertRaises(envrune.EnvruneError) as raised:
            envrune.load(binary=binary)
        self.assertEqual(str(raised.exception), "The vault is locked. Run `envrune unlock` first.")


class MissingBinaryTest(unittest.TestCase):
    def test_says_how_to_fix_it(self):
        with self.assertRaises(envrune.EnvruneError) as raised:
            envrune.load(binary=os.path.join(tempfile.gettempdir(), "no-such-envrune-binary"))
        self.assertIn("not found", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
