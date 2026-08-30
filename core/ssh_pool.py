# -*- coding: utf-8 -*-
"""Dedicated bounded executor for blocking device SSH work (WP11,
docs/app-review-fix-plan.md).

FastAPI sync routes and ``asyncio.to_thread`` share the default anyio pool
(~40 workers): a few 15–90 second netmiko sessions can sit on all of it and
stall every unrelated endpoint. Long device work goes through this pool
instead, so the web surface stays responsive while devices are slow.
"""

import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor

SSH_EXECUTOR_MAX_WORKERS = 16

ssh_executor = ThreadPoolExecutor(
    max_workers=SSH_EXECUTOR_MAX_WORKERS, thread_name_prefix="device-ssh")


async def run_ssh(fn, *args, **kwargs):
    """Runs blocking device work on the SSH pool from an async handler."""
    loop = asyncio.get_running_loop()
    call = functools.partial(fn, *args, **kwargs)
    return await loop.run_in_executor(ssh_executor, call)
