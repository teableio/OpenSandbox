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

func TestCredentialIsCurrentProcess_GroupsWeDoNotHold(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	current, err := os.Getgroups()
	require.NoError(t, err)

	unheld := uint32(gid + 4242)
	for _, g := range current {
		if uint32(g) == unheld {
			t.Skip("picked group is actually held; skipping to stay deterministic")
		}
	}

	// Inheriting would silently drop a group the caller asked for.
	assert.False(t, credentialIsCurrentProcess(
		&syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{unheld}}))
}

func TestGroupsAreSubset(t *testing.T) {
	const primary = uint32(1000)

	// Equal sets — the production case (image NSS groups match the runtime's).
	assert.True(t, groupsAreSubset([]uint32{1000}, []int{1000}, primary))
	// Primary gid counts as held even when getgroups(2) omits it, and as
	// requested even when the caller omits it.
	assert.True(t, groupsAreSubset([]uint32{1000}, []int{}, primary))
	assert.True(t, groupsAreSubset(nil, []int{1000}, primary))
	// Extra groups we hold (e.g. pod-level supplementalGroups) are fine.
	assert.True(t, groupsAreSubset([]uint32{1000}, []int{1000, 2000}, primary))
	// A requested group we do not hold must not be inherited away.
	assert.False(t, groupsAreSubset([]uint32{1000, 3000}, []int{1000}, primary))
	// Defensive: a negative gid from the platform is never treated as held.
	assert.False(t, groupsAreSubset([]uint32{7}, []int{-1}, primary))
}
