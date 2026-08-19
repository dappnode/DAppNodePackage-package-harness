use std::fmt::{Display, Formatter};

use dappnode_types::{DnpName, PackageRef};
use serde::{Deserialize, Serialize};

use super::DomainError;

macro_rules! string_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_newtype!(RunId);
string_newtype!(RepositoryName);
string_newtype!(HeadSha);

impl RunId {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let value = bounded(value, "runId", 1, 128)?;
        if !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        {
            return Err(validation("runId", "contains unsafe characters"));
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunRequestDto {
    pub schema_version: u8,
    pub run_id: String,
    pub source: SourceDto,
    pub package: PackageRequestDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceDto {
    pub repository: String,
    pub pull_request: u64,
    pub head_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageRequestDto {
    pub dnp_name: String,
    pub candidate_ref: String,
    #[serde(default)]
    pub baseline_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunRequest {
    pub schema_version: u8,
    pub run_id: RunId,
    pub source: RunSource,
    pub package: PackageRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSource {
    pub repository: RepositoryName,
    pub pull_request: u64,
    pub head_sha: HeadSha,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageRequest {
    pub dnp_name: DnpName,
    pub candidate_ref: PackageRef,
    pub baseline_ref: Option<PackageRef>,
}

impl TryFrom<RunRequestDto> for RunRequest {
    type Error = DomainError;

    fn try_from(dto: RunRequestDto) -> Result<Self, Self::Error> {
        if dto.schema_version != 1 {
            return Err(validation("schemaVersion", "only version 1 is supported"));
        }
        let run_id = RunId::parse(&dto.run_id)?;
        let repository = bounded(&dto.source.repository, "source.repository", 3, 200)?;
        let mut repository_parts = repository.split('/');
        let valid_repository = repository_parts.next().is_some_and(valid_repository_part)
            && repository_parts.next().is_some_and(valid_repository_part)
            && repository_parts.next().is_none();
        if !valid_repository {
            return Err(validation(
                "source.repository",
                "must be an ASCII owner/repository name",
            ));
        }
        if dto.source.pull_request == 0 {
            return Err(validation("source.pullRequest", "must be positive"));
        }
        let head_sha = bounded(&dto.source.head_sha, "source.headSha", 7, 64)?;
        if !head_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(validation(
                "source.headSha",
                "must contain only hexadecimal characters",
            ));
        }
        let dnp_name = DnpName::parse(&dto.package.dnp_name)
            .map_err(|error| validation("package.dnpName", &error.to_string()))?;
        let candidate_ref = parse_package_ref(&dto.package.candidate_ref, "package.candidateRef")?;
        let baseline_ref = dto
            .package
            .baseline_ref
            .as_deref()
            .map(|value| parse_package_ref(value, "package.baselineRef"))
            .transpose()?;

        Ok(Self {
            schema_version: 1,
            run_id,
            source: RunSource {
                repository: RepositoryName(repository.to_owned()),
                pull_request: dto.source.pull_request,
                head_sha: HeadSha(head_sha.to_owned()),
            },
            package: PackageRequest {
                dnp_name,
                candidate_ref,
                baseline_ref,
            },
        })
    }
}

fn valid_repository_part(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 100
        && part
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn bounded<'a>(
    value: &'a str,
    field: &'static str,
    minimum: usize,
    maximum: usize,
) -> Result<&'a str, DomainError> {
    let length = value.len();
    if !(minimum..=maximum).contains(&length) {
        return Err(validation(
            field,
            &format!("length must be between {minimum} and {maximum} bytes"),
        ));
    }
    Ok(value)
}

fn parse_package_ref(value: &str, field: &'static str) -> Result<PackageRef, DomainError> {
    PackageRef::parse(value).map_err(|error| validation(field, &error.to_string()))
}

fn validation(field: &'static str, message: &str) -> DomainError {
    DomainError::Validation {
        field,
        message: message.to_owned(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPackage {
    pub dnp_name: DnpName,
    pub candidate_ref: PackageRef,
    pub baseline_ref: Option<PackageRef>,
}

pub trait PackageResolver: Send + Sync {
    fn resolve(&self, request: &RunRequest) -> ResolvedPackage;
}

#[derive(Debug, Default)]
pub struct ExplicitPackageResolver;

impl PackageResolver for ExplicitPackageResolver {
    fn resolve(&self, request: &RunRequest) -> ResolvedPackage {
        ResolvedPackage {
            dnp_name: request.package.dnp_name.clone(),
            candidate_ref: request.package.candidate_ref.clone(),
            baseline_ref: request.package.baseline_ref.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PackageRequestDto, RunRequest, RunRequestDto, SourceDto};

    fn request(repository: &str, head_sha: &str) -> RunRequestDto {
        RunRequestDto {
            schema_version: 1,
            run_id: "run-01".to_owned(),
            source: SourceDto {
                repository: repository.to_owned(),
                pull_request: 1,
                head_sha: head_sha.to_owned(),
            },
            package: PackageRequestDto {
                dnp_name: "example.dnp.dappnode.eth".to_owned(),
                candidate_ref: "/ipfs/QmCandidate".to_owned(),
                baseline_ref: None,
            },
        }
    }

    #[test]
    fn source_identifiers_are_safe_for_github_links() {
        assert!(RunRequest::try_from(request("dappnode/example-package", "abcdef0")).is_ok());
        assert!(RunRequest::try_from(request("dappnode/example?tab=bad", "abcdef0")).is_err());
        assert!(RunRequest::try_from(request("dappnode/example", "../main")).is_err());
        assert!(RunRequest::try_from(request("dappnode/example", "not-a-sha")).is_err());
    }
}
