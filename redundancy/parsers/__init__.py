# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
from typing import Callable, Any

CLI_PARSERS: dict[tuple[str, str], Callable[..., Any]] = {}
