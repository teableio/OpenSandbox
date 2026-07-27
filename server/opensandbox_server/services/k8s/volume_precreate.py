# Copyright 2026 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Control-plane pre-creation of PVC subPath directories.

kubelet creates missing subPath directories owned by root:root (0755), which a
non-root sandbox user cannot write to. When ``kubernetes.volume_subpath_precreate``
is configured, the server creates the requested directories itself — owned by
the configured uid/gid — before the workload is created, so sandbox pods never
need root to fix ownership.
"""

import logging
import os
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from opensandbox_server.api.schema import Volume
    from opensandbox_server.config import VolumeSubpathPrecreate

logger = logging.getLogger(__name__)


def precreate_volume_subpaths(
    volumes: Optional[List["Volume"]],
    precreate: Optional["VolumeSubpathPrecreate"],
) -> None:
    """Create missing subPath directories for read-write PVC volumes.

    Only claims listed in ``precreate.mounts`` are handled; read-only volumes
    (externally provisioned content such as skills) are skipped. Ownership is
    only applied to directories this call creates — pre-existing directories
    are never touched.

    Raises ``RuntimeError`` when a directory cannot be created or chowned:
    failing the sandbox create loudly beats handing out a workspace the
    sandbox user cannot write to.
    """
    if not volumes or not precreate or not precreate.mounts:
        return

    for vol in volumes:
        if vol.pvc is None or vol.read_only or not vol.sub_path:
            continue
        root = precreate.mounts.get(vol.pvc.claim_name)
        if root is None:
            logger.debug(
                "subPath precreate: claim %s not in mounts map, skipping",
                vol.pvc.claim_name,
            )
            continue
        _makedirs_owned(
            root=root,
            sub_path=vol.sub_path,
            uid=precreate.uid,
            gid=precreate.gid,
            dir_mode=precreate.dir_mode,
        )


def _makedirs_owned(root: str, sub_path: str, uid: int, gid: int, dir_mode: int) -> None:
    """Create ``root/sub_path`` component by component, owned by ``uid:gid``.

    Each component is opened relative to its parent's file descriptor with
    ``O_NOFOLLOW``, so a symlink planted between the path check and the
    creation cannot redirect the walk outside the mount root. Existing
    components must already be real directories; anything else is an error
    rather than a silently accepted path.
    """
    root_real = os.path.realpath(root)
    normalized = os.path.normpath(os.path.join(root_real, sub_path))
    if normalized != root_real and not normalized.startswith(root_real + os.sep):
        raise RuntimeError(
            f"subPath precreate: '{sub_path}' escapes the mount root '{root}'"
        )

    relative = os.path.relpath(normalized, root_real)
    if relative == os.curdir:
        return

    # chown(2) needs CAP_CHOWN; when the server already runs as the target
    # owner, created directories inherit the right ownership and chown must be
    # skipped or it would fail with EPERM.
    chown_needed = not (os.geteuid() == uid and os.getegid() == gid)

    try:
        parent_fd = os.open(root_real, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise RuntimeError(
            f"subPath precreate: cannot open mount root '{root}': {exc}"
        ) from exc

    walked = root_real
    try:
        for part in relative.split(os.sep):
            walked = os.path.join(walked, part)
            child_fd = _mkdir_or_open_dir(
                parent_fd=parent_fd,
                name=part,
                path_for_errors=walked,
                uid=uid,
                gid=gid,
                dir_mode=dir_mode,
                chown_needed=chown_needed,
            )
            os.close(parent_fd)
            parent_fd = child_fd
    finally:
        os.close(parent_fd)


def _mkdir_or_open_dir(
    *,
    parent_fd: int,
    name: str,
    path_for_errors: str,
    uid: int,
    gid: int,
    dir_mode: int,
    chown_needed: bool,
) -> int:
    """Create ``name`` under ``parent_fd`` (or adopt it) and return its fd."""
    created = True
    try:
        os.mkdir(name, dir_mode, dir_fd=parent_fd)
    except FileExistsError:
        created = False
    except OSError as exc:
        raise RuntimeError(
            f"subPath precreate: cannot create '{path_for_errors}': {exc}"
        ) from exc

    try:
        # O_NOFOLLOW rejects a symlink planted in place of the component: a
        # concurrent writer cannot make the walk continue outside the volume.
        fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise RuntimeError(
            f"subPath precreate: '{path_for_errors}' exists but is not a "
            f"directory (or is a symlink): {exc}"
        ) from exc

    if not created:
        # Converge ownership of directories we adopt. This is idempotent, so
        # concurrent replicas agree, and it closes two gaps: another replica
        # that created the directory but has not chowned it yet, and legacy
        # directories kubelet created as root before this feature existed.
        # Only the directory entry itself is touched, never its contents.
        if chown_needed:
            try:
                stat_result = os.fstat(fd)
                if stat_result.st_uid != uid or stat_result.st_gid != gid:
                    os.fchown(fd, uid, gid)
                    logger.info(
                        "subPath precreate: adopted %s, owner corrected to %s:%s",
                        path_for_errors,
                        uid,
                        gid,
                    )
            except OSError as exc:
                os.close(fd)
                raise RuntimeError(
                    f"subPath precreate: cannot correct owner of existing "
                    f"'{path_for_errors}' to {uid}:{gid}: {exc}"
                ) from exc
        return fd

    try:
        # mkdir mode is masked by umask; restore the requested bits explicitly.
        os.fchmod(fd, dir_mode)
        if chown_needed:
            os.fchown(fd, uid, gid)
    except OSError as exc:
        # The directory exists but is not usable by the sandbox user, and a
        # retry would take the "already exists" path and skip the fix — so
        # remove it and let the caller retry from a clean state.
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            logger.warning(
                "subPath precreate: failed to roll back '%s' after an "
                "ownership error; it may stay root-owned",
                path_for_errors,
            )
        os.close(fd)
        raise RuntimeError(
            f"subPath precreate: cannot set owner {uid}:{gid} / mode "
            f"{dir_mode:o} on '{path_for_errors}': {exc}"
        ) from exc

    logger.info(
        "subPath precreate: created %s (owner %s:%s, mode %o)",
        path_for_errors,
        uid,
        gid,
        dir_mode,
    )
    return fd
