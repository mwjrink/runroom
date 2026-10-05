//! Stable identities carried through launch and lifecycle operations.

use std::num::NonZeroU32;

/// Canonical identity assigned by the selected workspace backend.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProjectId(pub String);

/// Human-supplied workspace name from `runroom --name <NAME>`.
///
/// Transport parsing will validate this value before constructing launch state.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WorkspaceName(pub String);

/// Unique identity for one launched foreground process tree.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InstanceId(pub String);

/// Operating-system process ID obtained from the local socket peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessId(pub NonZeroU32);

/// Operating-system user ID obtained from the local socket peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UserId(pub u32);
