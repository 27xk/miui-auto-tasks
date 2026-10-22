from pathlib import Path
from typing import Any


DEFAULT_SCENE = "GROW_UP_CHECKIN"
PACKAGE_DIR = Path(__file__).resolve().parent
ASSET_DIR = PACKAGE_DIR / "assets"
DEFAULT_PARAM_PATH = ASSET_DIR / "yzm.param"
DEFAULT_BIN_PATH = ASSET_DIR / "yzm.bin"


def solve_token(
    entry_url: str | None = None,
    uid: str = "",
    scene: str = DEFAULT_SCENE,
    **kwargs: Any,
) -> str:
    """Return a Xiaomi captcha token using the packaged captcha solver."""
    from .solve_captcha import solve_token as _solve_token

    kwargs.setdefault("param_path", DEFAULT_PARAM_PATH)
    kwargs.setdefault("bin_path", DEFAULT_BIN_PATH)
    return _solve_token(entry_url=entry_url, uid=uid, scene=scene, **kwargs)
