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
    root_real = os.path.realpath(root)
    target = os.path.realpath(os.path.join(root_real, sub_path))
    if target != root_real and not target.startswith(root_real + os.sep):
        raise RuntimeError(
            f"subPath precreate: '{sub_path}' escapes the mount root '{root}'"
        )

    relative = os.path.relpath(target, root_real)
    if relative == os.curdir:
        return

    # chown(2) needs CAP_CHOWN; when the server already runs as the target
    # owner, created directories inherit the right ownership and chown must be
    # skipped or it would fail with EPERM.
    chown_needed = not (os.geteuid() == uid and os.getegid() == gid)

    current = root_real
    for part in relative.split(os.sep):
        current = os.path.join(current, part)
        try:
            os.mkdir(current, dir_mode)
        except FileExistsError:
            continue
        except OSError as exc:
            raise RuntimeError(
                f"subPath precreate: cannot create '{current}': {exc}"
            ) from exc
        # mkdir mode is masked by umask; restore the requested bits explicitly.
        os.chmod(current, dir_mode)
        if chown_needed:
            try:
                os.chown(current, uid, gid)
            except OSError as exc:
                raise RuntimeError(
                    f"subPath precreate: cannot chown '{current}' to "
                    f"{uid}:{gid}: {exc}"
                ) from exc
        logger.info(
            "subPath precreate: created %s (owner %s:%s, mode %o)",
            current,
            uid,
            gid,
            dir_mode,
        )
