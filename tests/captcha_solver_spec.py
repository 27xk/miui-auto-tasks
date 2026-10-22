import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class CaptchaSolverTokenSpec(unittest.TestCase):
    def test_get_token_by_captcha_uses_solver_with_entry_url_and_uid(self):
        fake_request = types.ModuleType("utils.request")
        fake_request.post = lambda *args, **kwargs: None
        sys.modules.pop("utils.utils", None)

        calls = []

        def fake_solve_token(entry_url=None, uid="", scene="GROW_UP_CHECKIN", **kwargs):
            calls.append((entry_url, uid, scene, kwargs))
            return "token-123"

        with patch.dict(sys.modules, {"utils.request": fake_request}):
            from utils import utils as utils_mod

        with patch.object(utils_mod, "solve_captcha_token", fake_solve_token):
            result = utils_mod.get_token_by_captcha(
                "https://example.test/captcha?c=gt&l=challenge",
                uid="10001",
            )

        self.assertEqual(result, "token-123")
        self.assertEqual(
            calls,
            [
                (
                    "https://example.test/captcha?c=gt&l=challenge",
                    "10001",
                    "GROW_UP_CHECKIN",
                    {},
                )
            ],
        )

    def test_solver_default_assets_live_next_to_package(self):
        from utils.captcha_solver import DEFAULT_BIN_PATH, DEFAULT_PARAM_PATH

        assets_dir = ROOT / "utils" / "captcha_solver" / "assets"
        self.assertEqual(DEFAULT_PARAM_PATH, assets_dir / "yzm.param")
        self.assertEqual(DEFAULT_BIN_PATH, assets_dir / "yzm.bin")


if __name__ == "__main__":
    unittest.main()
