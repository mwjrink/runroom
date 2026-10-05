//! Typed one-request local control client.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::model::{
    InstanceId, InstanceRecord, PrunedWorktrees, RetiredWorkspace, ServiceAction, ServiceResult,
    StopMode, WorkspaceName,
};
use crate::protocol::{ControlOperation, ControlRequest, ControlResult};
use crate::transport::{connect_control, read_control_response, write_control_request};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Client for bounded lifecycle operations on the local Runroom daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostClient {
    socket_path: PathBuf,
}

impl HostClient {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
    /// Verify the live protocol with a bounded, read-only host operation.
    ///
    /// # Errors
    ///
    /// Returns connection, protocol, transport, or daemon rejection errors.
    pub fn verify(&self) -> io::Result<()> {
        self.list_instances(None, 1).map(|_| ())
    }

    /// List one bounded page of registered instances.
    ///
    /// # Errors
    ///
    /// Returns transport/protocol errors or daemon rejection of the page bounds.
    pub fn list_instances(
        &self,
        after: Option<InstanceId>,
        limit: u16,
    ) -> io::Result<Vec<InstanceRecord>> {
        match self.request(ControlOperation::ListInstances { after, limit })? {
            ControlResult::Instances(instances) => Ok(instances),
            _ => Err(unexpected_result()),
        }
    }

    /// Look up an instance visible to the caller.
    ///
    /// # Errors
    ///
    /// Returns transport/protocol errors or daemon authorization errors.
    pub fn get_instance(&self, id: InstanceId) -> io::Result<Option<InstanceRecord>> {
        match self.request(ControlOperation::GetInstance { id })? {
            ControlResult::Instance(instance) => Ok(instance),
            _ => Err(unexpected_result()),
        }
    }

    /// Request termination of a complete instance process tree.
    ///
    /// # Errors
    ///
    /// Returns transport/protocol errors, authorization errors, or stop failures.
    pub fn stop_instance(&self, id: InstanceId, mode: StopMode) -> io::Result<InstanceRecord> {
        match self.request(ControlOperation::StopInstance { id, mode })? {
            ControlResult::InstanceStopped(instance) => Ok(instance),
            _ => Err(unexpected_result()),
        }
    }

    /// Retire a managed worktree when no active instance uses its path.
    ///
    /// # Errors
    ///
    /// Returns transport/protocol errors or workspace authorization, activity,
    /// validation, and Git removal failures.
    pub fn retire_workspace(
        &self,
        current_directory: PathBuf,
        name: WorkspaceName,
    ) -> io::Result<RetiredWorkspace> {
        match self.request(ControlOperation::RetireWorkspace {
            current_directory,
            name,
        })? {
            ControlResult::WorkspaceRetired(workspace) => Ok(workspace),
            _ => Err(unexpected_result()),
        }
    }

    /// Prune stale Git worktree metadata for the caller's project.
    ///
    /// # Errors
    ///
    /// Returns transport/protocol errors or authorization and Git repair failures.
    pub fn repair_workspace_metadata(
        &self,
        current_directory: PathBuf,
    ) -> io::Result<PrunedWorktrees> {
        match self.request(ControlOperation::RepairWorkspaceMetadata { current_directory })? {
            ControlResult::WorkspaceMetadataRepaired(repair) => Ok(repair),
            _ => Err(unexpected_result()),
        }
    }
    /// Manage the caller's project services under a bounded execution deadline.
    ///
    /// # Errors
    ///
    /// Returns transport/protocol errors, invalid project/environment errors,
    /// service timeouts, output-limit errors, or Docker execution failures.
    pub fn manage_services(
        &self,
        current_directory: PathBuf,
        action: ServiceAction,
    ) -> io::Result<ServiceResult> {
        match self.request(ControlOperation::ManageServices {
            current_directory,
            action,
        })? {
            ControlResult::Services(result) => Ok(result),
            _ => Err(unexpected_result()),
        }
    }

    fn request(&self, operation: ControlOperation) -> io::Result<ControlResult> {
        let service_operation = matches!(operation, ControlOperation::ManageServices { .. });
        let mut stream = connect_control(&self.socket_path)?;
        if service_operation {
            stream.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
        }
        let request_id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        write_control_request(
            &mut stream,
            &ControlRequest {
                request_id,
                operation,
            },
        )?;
        let response = read_control_response(&mut stream)?;
        if response.request_id != request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon response request ID does not match",
            ));
        }
        response.result.map_err(|error| {
            io::Error::other(format!(
                "daemon rejected request [{}]: {}",
                error.code, error.message
            ))
        })
    }
}

fn unexpected_result() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "daemon returned a result for another operation",
    )
}
