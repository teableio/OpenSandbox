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

import os

import pytest

from opensandbox_server.api.schema import PVC, Volume
from opensandbox_server.config import VolumeSubpathPrecreate
from opensandbox_server.services.volume_precreate import precreate_volume_subpaths

# The feature targets Linux sandbox nodes and uses POSIX-only primitives
# (O_DIRECTORY/O_NOFOLLOW, mkdir(dir_fd=), fchown), so these tests only run
# there; on Windows the feature raises the platform guard instead.
pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="subPath precreate is POSIX-only"
)


def _rw_pvc_volume(claim: str, sub_path: str) -> Volume:
    return Volume(
        name="data",
        pvc=PVC(claim_name=claim),
        mount_path="/home/agent/data",
        read_only=False,
        sub_path=sub_path,
    )


@pytest.fixture
def fchown_recorder(monkeypatch):
    """Force the chown branch and record calls instead of touching the OS.

    Tests run unprivileged, so a real fchown(2) to another uid would fail with
    EPERM; recording the (fd, uid, gid) triples keeps the assertions portable.
    """
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((fd, uid, gid)))
    return calls


class TestPrecreateVolumeSubpaths:

    def test_creates_nested_directories_with_ownership(self, tmp_path, fchown_recorder):
        precreate = VolumeSubpathPrecreate(
            uid=1000, gid=1000, mounts={"agent-data": str(tmp_path)}
        )

        precreate_volume_subpaths(
            [_rw_pvc_volume("agent-data", "teable/user/u1/agent/uploads")], precreate
        )

        target = tmp_path / "teable" / "user" / "u1" / "agent" / "uploads"
        assert target.is_dir()
        # One ownership call per created component, root itself untouched.
        assert len(fchown_recorder) == 5
        assert all(call[1:] == (1000, 1000) for call in fchown_recorder)

    def test_existing_directories_are_not_recreated(self, tmp_path, fchown_recorder):
        existing = tmp_path / "teable" / "user"
        existing.mkdir(parents=True)
        os.chmod(existing, 0o700)
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        precreate_volume_subpaths(
            [_rw_pvc_volume("agent-data", "teable/user/u1")], precreate
        )

        assert (existing / "u1").is_dir()
        # Existing dirs keep their mode; only ownership converges (2 adopted
        # dirs owned by the test user + 1 newly created).
        assert existing.stat().st_mode & 0o777 == 0o700

    def test_adopted_directory_ownership_converges(self, tmp_path, monkeypatch):
        """A dir created by another replica (or legacy kubelet) gets chowned."""
        chowned = []
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.setattr(os, "getegid", lambda: 0)
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: chowned.append((uid, gid)))
        existing = tmp_path / "teable"
        existing.mkdir()
        # Target owner differs from the dir's real owner, so convergence must
        # fire — pick a uid the test process cannot already be.
        target_uid = existing.stat().st_uid + 1
        precreate = VolumeSubpathPrecreate(
            uid=target_uid, gid=1000, mounts={"agent-data": str(tmp_path)}
        )

        precreate_volume_subpaths([_rw_pvc_volume("agent-data", "teable")], precreate)

        assert chowned == [(target_uid, 1000)]

    def test_adopted_directory_with_matching_owner_is_left_alone(
        self, tmp_path, monkeypatch
    ):
        chowned = []
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.setattr(os, "getegid", lambda: 0)
        monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: chowned.append((uid, gid)))
        existing = tmp_path / "teable"
        existing.mkdir()
        stat_result = existing.stat()
        precreate = VolumeSubpathPrecreate(
            uid=stat_result.st_uid,
            gid=stat_result.st_gid,
            mounts={"agent-data": str(tmp_path)},
        )

        precreate_volume_subpaths([_rw_pvc_volume("agent-data", "teable")], precreate)

        assert chowned == []

    def test_fully_existing_subpath_needs_no_creation(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.setattr(os, "getegid", lambda: 1000)
        calls = []
        monkeypatch.setattr(os, "fchown", lambda *a: calls.append(a))
        (tmp_path / "teable" / "user").mkdir(parents=True)
        precreate = VolumeSubpathPrecreate(
            uid=1000, gid=1000, mounts={"agent-data": str(tmp_path)}
        )

        precreate_volume_subpaths(
            [_rw_pvc_volume("agent-data", "teable/user")], precreate
        )

        assert calls == []

    def test_skips_read_only_unmapped_and_subpathless_volumes(self, tmp_path):
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})
        read_only = Volume(
            name="skills",
            pvc=PVC(claim_name="agent-data"),
            mount_path="/skills",
            read_only=True,
            sub_path="skills/shared",
        )
        unmapped = _rw_pvc_volume("other-claim", "teable/x")
        no_subpath = Volume(
            name="whole",
            pvc=PVC(claim_name="agent-data"),
            mount_path="/whole",
            read_only=False,
        )

        precreate_volume_subpaths([read_only, unmapped, no_subpath], precreate)

        assert list(tmp_path.iterdir()) == []

    def test_none_volumes_or_config_is_noop(self, tmp_path):
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        precreate_volume_subpaths(None, precreate)
        precreate_volume_subpaths([], precreate)
        precreate_volume_subpaths([_rw_pvc_volume("agent-data", "a/b")], None)

        assert list(tmp_path.iterdir()) == []

    def test_traversal_subpath_is_rejected(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(root)})

        with pytest.raises(RuntimeError, match="escapes the mount root"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "../evil")], precreate
            )

        assert not (tmp_path / "evil").exists()

    def test_symlinked_component_is_rejected(self, tmp_path):
        """A symlink planted in the path must not redirect the walk."""
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (root / "teable").symlink_to(outside)
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(root)})

        with pytest.raises(RuntimeError, match="is not a directory"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable/user")], precreate
            )

        assert list(outside.iterdir()) == []

    def test_existing_file_in_path_is_rejected(self, tmp_path):
        (tmp_path / "teable").write_text("not a directory")
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        with pytest.raises(RuntimeError, match="is not a directory"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable/user")], precreate
            )

    def test_chown_skipped_when_server_runs_as_target_owner(self, tmp_path, monkeypatch):
        calls = []
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.setattr(os, "getegid", lambda: 1000)
        monkeypatch.setattr(os, "fchown", lambda *a: calls.append(a))
        precreate = VolumeSubpathPrecreate(
            uid=1000, gid=1000, mounts={"agent-data": str(tmp_path)}
        )

        precreate_volume_subpaths(
            [_rw_pvc_volume("agent-data", "teable/user")], precreate
        )

        assert (tmp_path / "teable" / "user").is_dir()
        assert calls == []

    def test_chown_failure_rolls_back_created_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.setattr(os, "getegid", lambda: 0)

        def _fail(fd, uid, gid):
            raise PermissionError("op not permitted")

        monkeypatch.setattr(os, "fchown", _fail)
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        with pytest.raises(RuntimeError, match="cannot set owner"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable/user")], precreate
            )

        # Rolled back, so a retry starts clean instead of adopting a
        # root-owned directory forever.
        assert not (tmp_path / "teable").exists()

    def test_created_mode_survives_umask(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.setattr(os, "getegid", lambda: 1000)
        old_umask = os.umask(0o077)
        try:
            precreate = VolumeSubpathPrecreate(
                uid=1000, gid=1000, dir_mode=0o755, mounts={"agent-data": str(tmp_path)}
            )
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable")], precreate
            )
        finally:
            os.umask(old_umask)

        assert (tmp_path / "teable").stat().st_mode & 0o777 == 0o755

    def test_missing_mount_root_raises(self, tmp_path):
        precreate = VolumeSubpathPrecreate(
            mounts={"agent-data": str(tmp_path / "not-mounted")}
        )

        with pytest.raises(RuntimeError, match="cannot open mount root"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable")], precreate
            )

    def test_mount_root_swapped_after_resolution_is_rejected(
        self, tmp_path, monkeypatch
    ):
        """The root itself must not be a symlink at open time.

        realpath() resolves links at check time, so the only way the resolved
        root can be a symlink is the TOCTOU window between resolution and
        open — simulated here by resolving to a path that is a symlink.
        """
        real_root = tmp_path / "real"
        real_root.mkdir()
        swapped = tmp_path / "swapped"
        swapped.symlink_to(tmp_path / "elsewhere")
        (tmp_path / "elsewhere").mkdir()
        monkeypatch.setattr(os.path, "realpath", lambda p: str(swapped))

        with pytest.raises(RuntimeError, match="cannot open mount root"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable")],
                VolumeSubpathPrecreate(mounts={"agent-data": str(real_root)}),
            )

        assert list((tmp_path / "elsewhere").iterdir()) == []

    def test_chmod_failure_is_wrapped_and_rolls_back(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.setattr(os, "getegid", lambda: 1000)

        def _fail(fd, mode):
            raise PermissionError("op not permitted")

        monkeypatch.setattr(os, "fchmod", _fail)
        precreate = VolumeSubpathPrecreate(
            uid=1000, gid=1000, mounts={"agent-data": str(tmp_path)}
        )

        with pytest.raises(RuntimeError, match="cannot set owner"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable")], precreate
            )

        assert not (tmp_path / "teable").exists()

    def test_rollback_skips_a_concurrently_replaced_directory(
        self, tmp_path, monkeypatch
    ):
        """A racing replica's directory must survive our rollback."""
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.setattr(os, "getegid", lambda: 0)
        target = tmp_path / "teable"

        def _swap_then_fail(fd, uid, gid):
            # Stand in for another replica: move ours away, create its own.
            os.rename(target, tmp_path / "moved-away")
            target.mkdir()
            (target / "marker").write_text("other replica")
            raise PermissionError("op not permitted")

        monkeypatch.setattr(os, "fchown", _swap_then_fail)
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        with pytest.raises(RuntimeError, match="cannot set owner"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable")], precreate
            )

        assert (target / "marker").exists()

    def test_no_file_descriptor_leak(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.setattr(os, "getegid", lambda: 1000)
        precreate = VolumeSubpathPrecreate(
            uid=1000, gid=1000, mounts={"agent-data": str(tmp_path)}
        )
        (tmp_path / "existing").mkdir()

        before = _open_fd_count()
        precreate_volume_subpaths(
            [_rw_pvc_volume("agent-data", "a/b/c"),
             _rw_pvc_volume("agent-data", "existing/d")],
            precreate,
        )
        with pytest.raises(RuntimeError):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "../escape")], precreate
            )
        (tmp_path / "afile").write_text("x")
        with pytest.raises(RuntimeError):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "afile/nested")], precreate
            )

        assert _open_fd_count() == before

    def test_non_posix_platform_is_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "name", "nt")
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        with pytest.raises(RuntimeError, match="requires a POSIX host"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable")], precreate
            )


def _open_fd_count() -> int:
    """Count this process's open file descriptors (POSIX only)."""
    for fd_dir in ("/proc/self/fd", "/dev/fd"):
        if os.path.isdir(fd_dir):
            return len(os.listdir(fd_dir))
    raise RuntimeError("no fd directory available on this platform")
