// Copyright 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package runtime

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecWithSelfCredential_Unprivileged is the regression this fix exists
// for: setgroups(2) requires CAP_SETGID unconditionally, so an unprivileged
// process cannot spawn a child with an explicit Credential — not even for its
// own identity. Inheriting instead must work.
//
// Linux-only: the capability model this asserts is Linux-specific. Skipped
// when the test runs privileged (CI often runs as root in a container), where
// the syscall is permitted and there is nothing to reproduce.
func TestExecWithSelfCredential_Unprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("privileged: setgroups is permitted, the EPERM path cannot be reproduced")
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())

	explicit := exec.Command("/bin/sh", "-c", "true")
	explicit.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{gid}},
	}
	assert.Error(t, explicit.Run(), "explicit self-credential is expected to fail unprivileged")

	cred, err := buildCredential(&uid, &gid)
	require.NoError(t, err)
	require.Nil(t, cred, "self-identity must not request a credential switch")

	inherited := exec.Command("/bin/sh", "-c", "true")
	inherited.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	assert.NoError(t, inherited.Run(), "the child must inherit our identity and run")
}

// TestExecInheritsRequestedIdentity proves the child really ends up with the
// requested uid/gid, rather than merely starting successfully.
func TestExecInheritsRequestedIdentity(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	cred, err := buildCredential(&uid, &gid)
	require.NoError(t, err)

	cmd := exec.Command("/bin/sh", "-c", "id -u; id -g")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	out, err := cmd.Output()
	require.NoError(t, err)

	assert.Equal(t, []string{
		strconv.FormatUint(uint64(uid), 10),
		strconv.FormatUint(uint64(gid), 10),
	}, strings.Fields(string(out)))
}
