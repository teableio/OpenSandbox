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

//go:build !windows
// +build !windows

package runtime

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func u32(v int) *uint32 {
	x := uint32(v)
	return &x
}

func TestBuildCredential_NilWhenUnset(t *testing.T) {
	cred, err := buildCredential(nil, nil)

	require.NoError(t, err)
	assert.Nil(t, cred)
}

func TestBuildCredential_NilWhenRequestingCurrentIdentity(t *testing.T) {
	// Asking to run as the user we already are is a no-op switch. Returning a
	// Credential here would make the child call setgroups(2), which needs
	// CAP_SETGID — unavailable to an unprivileged sandbox container.
	cred, err := buildCredential(u32(os.Getuid()), u32(os.Getgid()))

	require.NoError(t, err)
	assert.Nil(t, cred, "no credential switch should be requested for the current identity")
}

func TestBuildCredential_SetWhenRequestingDifferentIdentity(t *testing.T) {
	otherUID := os.Getuid() + 1

	cred, err := buildCredential(u32(otherUID), u32(os.Getgid()))

	require.NoError(t, err)
	require.NotNil(t, cred, "a real identity change must still switch credentials")
	assert.Equal(t, uint32(otherUID), cred.Uid)
}

func TestBuildCredential_SetWhenOnlyGidDiffers(t *testing.T) {
	otherGID := os.Getgid() + 1

	cred, err := buildCredential(u32(os.Getuid()), u32(otherGID))

	require.NoError(t, err)
	require.NotNil(t, cred, "a group-only change must still switch credentials")
	assert.Equal(t, uint32(otherGID), cred.Gid)
}

func TestCredentialIsCurrentProcess(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())

	assert.True(t, credentialIsCurrentProcess(&syscall.Credential{Uid: uid, Gid: gid}))
	assert.False(t, credentialIsCurrentProcess(&syscall.Credential{Uid: uid + 1, Gid: gid}))
	assert.False(t, credentialIsCurrentProcess(&syscall.Credential{Uid: uid, Gid: gid + 1}))
}

// TestExecWithSelfCredential_Unprivileged is the regression this fix exists for:
// as an unprivileged user, spawning a child with an explicit Credential for our
// own identity fails with EPERM, while inheriting credentials succeeds.
func TestExecWithSelfCredential_Unprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can setgroups/setuid; the EPERM path only shows unprivileged")
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())

	explicit := exec.Command("/bin/sh", "-c", "true")
	explicit.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{gid}},
	}
	assert.Error(t, explicit.Run(), "explicit self-credential is expected to fail unprivileged")

	cred, err := buildCredential(&uid, &gid)
	require.NoError(t, err)
	inherited := exec.Command("/bin/sh", "-c", "true")
	inherited.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	assert.NoError(t, inherited.Run(), "buildCredential must let the child inherit our identity")
}
