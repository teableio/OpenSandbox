# Copyright 2026 The OpenSandbox Authors
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

from __future__ import annotations

from typing import Any

from docker.errors import DockerException
from fastapi import HTTPException, status

from opensandbox_server.services.constants import SandboxErrorCodes
from opensandbox_server.services.diagnostics import (
    DiagnosticContext,
    DiagnosticResult,
    limit_diagnostic_lines,
    unsupported_scope_error,
)

_SUPPORTED_LOG_SCOPES = ("container", "all")
_SUPPORTED_EVENT_SCOPES = ("runtime", "all")
_STABLE_LOG_LINE_LIMIT = 100
_STABLE_EVENT_LINE_LIMIT = 50


def _container_lifecycle_state(container: Any) -> tuple[str, str, str]:
    """Classify container inspect data without looking up its image."""
    state = container.attrs.get("State", {})
    status_value = (state.get("Status") or container.status or "").lower()
    if state.get("Running", False) and not state.get("Paused", False):
        return "Running", "CONTAINER_RUNNING", "Sandbox container is running."
    if state.get("Paused", False):
        return "Paused", "CONTAINER_PAUSED", "Sandbox container is paused."
    if state.get("Restarting", False):
        return "Running", "CONTAINER_RESTARTING", "Sandbox container is restarting."
    if status_value in {"created", "starting"}:
        return "Pending", "CONTAINER_STARTING", "Sandbox container is starting."
    if status_value in {"exited", "dead"}:
        exit_code = state.get("ExitCode")
        if exit_code == 0:
            return "Terminated", "CONTAINER_EXITED", "Sandbox container exited successfully."
        return "Failed", "CONTAINER_EXITED_ERROR", f"Sandbox container exited with code {exit_code}."
    return "Unknown", "CONTAINER_STATE_UNKNOWN", f"Sandbox container is in state '{status_value or 'unknown'}'."


class DockerDiagnosticsMixin:


    def get_sandbox_diagnostic_context(self, sandbox_id: str) -> DiagnosticContext:
        container = self._get_container_by_sandbox_id(sandbox_id)
        # Container lookup already provides inspect data. Do not construct a full
        # Sandbox here: that also inspects the image, which may no longer exist.
        state, _, _ = _container_lifecycle_state(container)
        return DiagnosticContext(
            sandbox_id=sandbox_id,
            state=state,
            backend_type="docker",
            backend_identifiers={"containerId": container.id, "containerName": container.name},
        )

    def get_sandbox_log_diagnostics(
        self,
        sandbox_id: str,
        scope: str,
    ) -> DiagnosticResult:
        """Collect stable log diagnostics using Docker capabilities."""
        normalized_scope = scope.strip().lower()
        if normalized_scope not in _SUPPORTED_LOG_SCOPES:
            raise unsupported_scope_error("logs", scope, _SUPPORTED_LOG_SCOPES)

        content = self.get_sandbox_logs(
            sandbox_id,
            tail=_STABLE_LOG_LINE_LIMIT + 1,
        )
        content, truncated = limit_diagnostic_lines(
            content,
            _STABLE_LOG_LINE_LIMIT,
            keep_tail=True,
        )
        warnings: tuple[str, ...] = ()
        if normalized_scope == "all":
            warnings = (
                "The current backend only contributes sandbox container logs to the all scope.",
            )
        return DiagnosticResult(
            sandbox_id=sandbox_id,
            kind="logs",
            scope=normalized_scope,
            content=content,
            truncated=truncated,
            warnings=warnings,
        )

    def get_sandbox_event_diagnostics(
        self,
        sandbox_id: str,
        scope: str,
    ) -> DiagnosticResult:
        """Collect stable event diagnostics using Docker capabilities."""
        normalized_scope = scope.strip().lower()
        if normalized_scope not in _SUPPORTED_EVENT_SCOPES:
            raise unsupported_scope_error("events", scope, _SUPPORTED_EVENT_SCOPES)

        content = self.get_sandbox_events(
            sandbox_id,
            limit=_STABLE_EVENT_LINE_LIMIT + 1,
        )
        content, truncated = limit_diagnostic_lines(
            content,
            _STABLE_EVENT_LINE_LIMIT,
            keep_tail=False,
        )
        warnings: tuple[str, ...] = ()
        if normalized_scope == "all":
            warnings = ("The current backend only contributes runtime events to the all scope.",)
        return DiagnosticResult(
            sandbox_id=sandbox_id,
            kind="events",
            scope=normalized_scope,
            content=content,
            truncated=truncated,
            warnings=warnings,
        )

    def get_sandbox_logs(
        self,
        sandbox_id: str,
        tail: int = 100,
    ) -> str:
        docker_container = self._get_container_by_sandbox_id(sandbox_id)
        kwargs: dict = {"tail": tail, "timestamps": True}
        try:
            output = docker_container.logs(**kwargs)
        except DockerException as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.CONTAINER_QUERY_FAILED,
                    "message": f"Failed to read logs for sandbox {sandbox_id}: {exc}",
                },
            ) from exc
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return output or "(no logs)"

    # Teable fork: upstream removed this deprecated DevOps inspect in 1.3.0-rc.1
    # (92a6f29e1). The Teable backend still parses its plain text to detect pods
    # that died after start-up and OOM kills, because controller v0.2.0 keeps such
    # sandboxes Running. Restored verbatim; drop once the backend reads the
    # sandbox status (controller >= 1.1.0 reports PodFailed / status.message).
    def get_sandbox_inspect(self, sandbox_id: str) -> str:
        container = self._get_container_by_sandbox_id(sandbox_id)
        attrs = container.attrs or {}
        state = attrs.get("State", {})
        config_section = attrs.get("Config", {})
        network_settings = attrs.get("NetworkSettings", {}) or {}
        host_config = attrs.get("HostConfig", {}) or {}

        lines: list[str] = []
        lines.append(f"Container ID:   {container.id[:12]}")
        lines.append(f"Name:           {container.name}")
        lines.append(f"Image:          {config_section.get('Image', 'N/A')}")
        lines.append(f"Status:         {state.get('Status', 'unknown')}")
        lines.append(f"Running:        {state.get('Running', False)}")
        lines.append(f"Paused:         {state.get('Paused', False)}")
        lines.append(f"OOMKilled:      {state.get('OOMKilled', False)}")
        lines.append(f"Exit Code:      {state.get('ExitCode', 'N/A')}")
        lines.append(f"Started At:     {state.get('StartedAt', 'N/A')}")
        lines.append(f"Finished At:    {state.get('FinishedAt', 'N/A')}")
        if state.get("Error"):
            lines.append(f"Error:          {state['Error']}")

        lines.append("")
        lines.append("Resources:")
        nano_cpus = host_config.get("NanoCpus", 0)
        if nano_cpus:
            lines.append(f"  CPU:          {nano_cpus / 1e9:.2f} cores")
        memory = host_config.get("Memory", 0)
        if memory:
            lines.append(f"  Memory:       {memory // (1024 * 1024)} MiB")
        pids_limit = host_config.get("PidsLimit", 0)
        if pids_limit:
            lines.append(f"  PIDs Limit:   {pids_limit}")

        lines.append("")
        lines.append("Network:")
        networks = network_settings.get("Networks", {})
        for net_name, net_info in networks.items():
            ip = (net_info or {}).get("IPAddress", "N/A")
            lines.append(f"  {net_name}: {ip}")

        ports = network_settings.get("Ports", {})
        if ports:
            lines.append("")
            lines.append("Ports:")
            for port_key, bindings in (ports or {}).items():
                if bindings:
                    for b in bindings:
                        lines.append(f"  {port_key} -> {b.get('HostIp', '')}:{b.get('HostPort', '')}")
                else:
                    lines.append(f"  {port_key} (not bound)")

        labels = config_section.get("Labels", {})
        if labels:
            lines.append("")
            lines.append("Labels:")
            for k, v in sorted(labels.items()):
                lines.append(f"  {k}={v}")

        env_list = config_section.get("Env", [])
        if env_list:
            lines.append("")
            lines.append("Environment:")
            for env_entry in env_list:
                key = env_entry.split("=", 1)[0] if "=" in env_entry else env_entry
                if any(s in key.upper() for s in ("SECRET", "TOKEN", "PASSWORD", "KEY")):
                    lines.append(f"  {key}=***")
                else:
                    lines.append(f"  {env_entry}")

        return "\n".join(lines)

    def get_sandbox_events(self, sandbox_id: str, limit: int = 50) -> str:
        container = self._get_container_by_sandbox_id(sandbox_id)
        attrs = container.attrs or {}
        state = attrs.get("State", {})

        lines: list[str] = []

        # Docker does not have a per-container event history in the same way
        # K8s does. We reconstruct key state transitions from container attrs.
        lines.append(f"Container:  {container.id[:12]} ({container.name})")
        lines.append(f"Status:     {state.get('Status', 'unknown')}")

        created = attrs.get("Created", "N/A")
        lines.append(f"Created:    {created}")
        started = state.get("StartedAt")
        if started and started != "0001-01-01T00:00:00Z":
            lines.append(f"Started:    {started}")
        finished = state.get("FinishedAt")
        if finished and finished != "0001-01-01T00:00:00Z":
            lines.append(f"Finished:   {finished}")

        if state.get("OOMKilled"):
            lines.append("Event:      OOMKilled - container was killed due to out-of-memory")
        exit_code = state.get("ExitCode")
        if exit_code is not None and exit_code != 0:
            lines.append(f"Event:      Exited with code {exit_code}")
        if state.get("Error"):
            lines.append(f"Event:      Error - {state['Error']}")

        health = state.get("Health", {})
        if health:
            lines.append(f"Health:     {health.get('Status', 'N/A')}")
            for entry in (health.get("Log") or [])[-limit:]:
                ts = entry.get("Start", "")
                exit_code_h = entry.get("ExitCode", "")
                output_h = (entry.get("Output") or "").strip()[:200]
                lines.append(f"  [{ts}] exit={exit_code_h} {output_h}")

        if len(lines) <= 3:
            lines.append("(no notable events)")

        return "\n".join(lines)
