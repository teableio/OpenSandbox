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

Both node runtimes create missing subPath directories owned by root:root
(0755), which a non-root sandbox user cannot write to: kubelet for PVC
subPaths, dockerd for the bind-mount sources the Docker runtime derives from a
named volume's Mountpoint + subPath. When ``kubernetes.volume_subpath_precreate``
or ``docker.volume_subpath_precreate`` is configured, the server creates the
requested directories itself — owned by the configured uid/gid — before the
workload or container is created, so sandboxes never need root to fix
ownership.
"""

import logging
import os
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from opensandbox_server.api.schema import Volume
    from opensandbox_server.config import VolumeSubpathPrecreate

logger = logging.getLogger(__name__)


def _require_posix() -> None:
    """Fail loudly on platforms without the POSIX primitives this needs.

    The safe walk relies on ``O_DIRECTORY``/``O_NOFOLLOW``, ``mkdir(dir_fd=)``
    and ``fchown``, none of which exist on Windows. The feature only makes
    sense for Linux sandbox nodes anyway; the explicit error beats an
    AttributeError deep in the create path.
    """
    if os.name != "posix":
        raise RuntimeError(
            "subPath precreate requires a POSIX host "
            f"(os.name={os.name!r}); disable volume_subpath_precreate"
        )


def precreate_volume_subpaths(
    volumes: Optional[List["Volume"]],
    precreate: Optional["VolumeSubpathPrecreate"],
) -> None:
    """Create missing subPath directories for read-write PVC volumes.

    Only claims listed in ``precreate.mounts`` are handled; read-only volumes
    (externally provisioned content such as skills) are skipped.

    Configuring a claim in ``mounts`` declares that the whole directory tree
    under that mount root is managed by this server for ``uid:gid`` — every
    component of a requested subPath is created with that owner, and an
    existing component's owner is converged to it. Do not point ``mounts`` at a
    volume whose directories are owned by someone else.

    Raises ``RuntimeError`` when a directory cannot be created or given the
    configured ownership: failing the sandbox create loudly beats handing out a
    workspace the sandbox user cannot write to.
    """
    if not volumes or not precreate or not precreate.mounts:
        return

    _require_posix()

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

    # O_NOFOLLOW also covers the realpath→open window on the root itself: if
    # the resolved root is swapped for a symlink in between, the open fails
    # instead of anchoring the whole walk outside the volume.
    try:
        parent_fd = os.open(root_real, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
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
        # directories the node runtime created as root before this feature
        # existed.
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
        # plain retry would take the "already exists" path — the adoption
        # branch above repairs ownership, but only remove the directory we
        # ourselves created so a concurrent creator's directory is never
        # deleted by our rollback.
        _rollback_created_dir(
            parent_fd=parent_fd,
            name=name,
            created_fd=fd,
            path_for_errors=path_for_errors,
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


def _rollback_created_dir(
    *, parent_fd: int, name: str, created_fd: int, path_for_errors: str
) -> None:
    """Remove ``name`` only if it is still the directory we created.

    Between our mkdir and this rollback another replica may have moved our
    directory away and created its own under the same name; comparing the
    entry's identity with our open fd keeps us from deleting theirs.

    A window remains between that comparison and the rmdir — POSIX has no
    "remove this open directory" call. The residual damage is bounded: rmdir
    only removes empty directories, and the next create re-creates and
    re-owns the entry, so a lost race costs one retry rather than data.
    """
    try:
        created_stat = os.fstat(created_fd)
        current_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (created_stat.st_dev, created_stat.st_ino) != (
            current_stat.st_dev,
            current_stat.st_ino,
        ):
            logger.warning(
                "subPath precreate: '%s' was replaced concurrently; skipping "
                "rollback so the other creator's directory survives",
                path_for_errors,
            )
            return
        os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        logger.warning(
            "subPath precreate: failed to roll back '%s' after an ownership "
            "error; a later create will repair its owner instead",
            path_for_errors,
        )
