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
from opensandbox_server.services.k8s.volume_precreate import precreate_volume_subpaths


def _rw_pvc_volume(claim: str, sub_path: str) -> Volume:
    return Volume(
        name="data",
        pvc=PVC(claim_name=claim),
        mount_path="/home/agent/data",
        read_only=False,
        sub_path=sub_path,
    )


@pytest.fixture
def chown_recorder(monkeypatch):
    """Force the chown branch and record calls instead of touching the OS."""
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: calls.append((path, uid, gid)))
    return calls


class TestPrecreateVolumeSubpaths:

    def test_creates_nested_directories_with_ownership(self, tmp_path, chown_recorder):
        precreate = VolumeSubpathPrecreate(
            uid=1000, gid=1000, mounts={"agent-data": str(tmp_path)}
        )

        precreate_volume_subpaths(
            [_rw_pvc_volume("agent-data", "teable/user/u1/agent/uploads")], precreate
        )

        target = tmp_path / "teable" / "user" / "u1" / "agent" / "uploads"
        assert target.is_dir()
        created = [call[0] for call in chown_recorder]
        assert str(target) in created
        # Every missing component is created and chowned, root itself untouched.
        assert len(created) == 5
        assert str(tmp_path) not in created
        assert all(call[1:] == (1000, 1000) for call in chown_recorder)

    def test_existing_directories_are_not_chowned(self, tmp_path, chown_recorder):
        existing = tmp_path / "teable" / "user"
        existing.mkdir(parents=True)
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        precreate_volume_subpaths(
            [_rw_pvc_volume("agent-data", "teable/user/u1")], precreate
        )

        created = [call[0] for call in chown_recorder]
        assert created == [str(existing / "u1")]

    def test_fully_existing_subpath_is_noop(self, tmp_path, chown_recorder):
        (tmp_path / "teable" / "user").mkdir(parents=True)
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        precreate_volume_subpaths(
            [_rw_pvc_volume("agent-data", "teable/user")], precreate
        )

        assert chown_recorder == []

    def test_skips_read_only_unmapped_and_subpathless_volumes(self, tmp_path, chown_recorder):
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
        assert chown_recorder == []

    def test_none_volumes_or_config_is_noop(self, tmp_path):
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        precreate_volume_subpaths(None, precreate)
        precreate_volume_subpaths([], precreate)
        precreate_volume_subpaths([_rw_pvc_volume("agent-data", "a/b")], None)

        assert list(tmp_path.iterdir()) == []

    def test_traversal_subpath_is_rejected(self, tmp_path, chown_recorder):
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path / "root")})
        (tmp_path / "root").mkdir()

        with pytest.raises(RuntimeError, match="escapes the mount root"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "../evil")], precreate
            )

        assert not (tmp_path / "evil").exists()

    def test_chown_skipped_when_server_runs_as_target_owner(self, tmp_path, monkeypatch):
        calls = []
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.setattr(os, "getegid", lambda: 1000)
        monkeypatch.setattr(os, "chown", lambda *a: calls.append(a))
        precreate = VolumeSubpathPrecreate(
            uid=1000, gid=1000, mounts={"agent-data": str(tmp_path)}
        )

        precreate_volume_subpaths(
            [_rw_pvc_volume("agent-data", "teable/user")], precreate
        )

        assert (tmp_path / "teable" / "user").is_dir()
        assert calls == []

    def test_chown_failure_raises_runtime_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.setattr(os, "getegid", lambda: 0)

        def _fail(path, uid, gid):
            raise PermissionError("op not permitted")

        monkeypatch.setattr(os, "chown", _fail)
        precreate = VolumeSubpathPrecreate(mounts={"agent-data": str(tmp_path)})

        with pytest.raises(RuntimeError, match="cannot chown"):
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable/user")], precreate
            )

    def test_created_mode_survives_umask(self, tmp_path, chown_recorder):
        old_umask = os.umask(0o077)
        try:
            precreate = VolumeSubpathPrecreate(
                dir_mode=0o755, mounts={"agent-data": str(tmp_path)}
            )
            precreate_volume_subpaths(
                [_rw_pvc_volume("agent-data", "teable")], precreate
            )
        finally:
            os.umask(old_umask)

        mode = (tmp_path / "teable").stat().st_mode & 0o777
        assert mode == 0o755
