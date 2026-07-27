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

from opensandbox_server.services.k8s.provider_common import (
    merge_template_security_context,
)


class TestMergeTemplateSecurityContext:

    def test_empty_sides_pass_through(self):
        runtime = {"capabilities": {"drop": ["NET_ADMIN"]}}
        template = {"allowPrivilegeEscalation": False}

        assert merge_template_security_context(None, runtime) == runtime
        assert merge_template_security_context({}, runtime) == runtime
        assert merge_template_security_context(template, None) == template
        assert merge_template_security_context(template, {}) == template

    def test_template_only_fields_are_kept(self):
        merged = merge_template_security_context(
            {"allowPrivilegeEscalation": False, "runAsNonRoot": True},
            {"capabilities": {"drop": ["NET_ADMIN"]}},
        )

        assert merged["allowPrivilegeEscalation"] is False
        assert merged["runAsNonRoot"] is True
        assert merged["capabilities"] == {"drop": ["NET_ADMIN"]}

    def test_runtime_scalar_wins_on_conflict(self):
        merged = merge_template_security_context(
            {"privileged": False, "readOnlyRootFilesystem": True},
            {"privileged": True},
        )

        assert merged["privileged"] is True
        assert merged["readOnlyRootFilesystem"] is True

    def test_runtime_dict_field_replaces_template_dict(self):
        merged = merge_template_security_context(
            {"seccompProfile": {"type": "RuntimeDefault"}},
            {"seccompProfile": {"type": "Unconfined"}},
        )

        assert merged["seccompProfile"] == {"type": "Unconfined"}

    def test_capability_lists_are_unioned(self):
        merged = merge_template_security_context(
            {"capabilities": {"drop": ["ALL"], "add": ["SYS_PTRACE"]}},
            {"capabilities": {"drop": ["NET_ADMIN"]}},
        )

        assert merged["capabilities"] == {
            "add": ["SYS_PTRACE"],
            "drop": ["ALL", "NET_ADMIN"],
        }

    def test_runtime_drop_beats_template_add(self):
        merged = merge_template_security_context(
            {"capabilities": {"add": ["NET_ADMIN", "SYS_PTRACE"]}},
            {"capabilities": {"drop": ["NET_ADMIN"]}},
        )

        # add and drop of the same capability is ambiguous (drops apply first,
        # so it would stay granted) — the runtime intent must survive.
        assert merged["capabilities"] == {"add": ["SYS_PTRACE"], "drop": ["NET_ADMIN"]}

    def test_runtime_add_beats_template_drop(self):
        merged = merge_template_security_context(
            {"capabilities": {"drop": ["SYS_ADMIN", "NET_RAW"]}},
            {"capabilities": {"add": ["SYS_ADMIN"]}},
        )

        assert merged["capabilities"] == {"add": ["SYS_ADMIN"], "drop": ["NET_RAW"]}

    def test_empty_capabilities_are_dropped_from_result(self):
        merged = merge_template_security_context(
            {"capabilities": {"add": ["SYS_ADMIN"]}, "runAsNonRoot": True},
            {"capabilities": {"drop": ["SYS_ADMIN"]}},
        )

        # The only add is cancelled by the runtime drop, which stays.
        assert merged["capabilities"] == {"drop": ["SYS_ADMIN"]}
        assert merged["runAsNonRoot"] is True

    def test_inputs_are_not_mutated(self):
        template = {"capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True}
        runtime = {"capabilities": {"drop": ["NET_ADMIN"]}}

        merge_template_security_context(template, runtime)

        assert template == {"capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True}
        assert runtime == {"capabilities": {"drop": ["NET_ADMIN"]}}
