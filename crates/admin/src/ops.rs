//! Multi-step admin operations. Each one runs in a single SQLite transaction together with the CA's
//! derived domain set, so a rule change and the CA it implies either both happen or neither does.
//! The CA certificate is persisted inside the transaction and installed in memory only after commit.
//!
//! Concurrency: every operation (and [`sync_ca`]) starts by taking `CaService::domain_guard()` and keeps it
//! until after `install`. The domain set is derived from the rules visible inside the transaction and then
//! compared with the in-memory CA, so two operations interleaving between "derive" and "install" could
//! install a stale set; the guard serialises them. It is acquired BEFORE `Vault::in_transaction` (the lock
//! order is guard -> vault connection -> CA state) and these functions never call `CaService::allow_domain`,
//! which takes the same lock and would self-deadlock. Hooks passed to the vault only use the `&Connection`
//! they receive, never `state.vault.conn()` or wrappers that lock it. `install` runs only after a
//! successful commit, never before.

use crate::{error::*, state::AppState};
use axum::http::StatusCode;
use rusqlite::Connection;
use sg_ca::{CaService, PreparedCa};
use sg_core::{SecretMeta, Vault};
use sg_policy::{derive_ca_domains, insert_rule_in, list_rules_in, NewRule, Rule, RuleSpec};

pub const MAX_RULES_PER_SECRET: usize = 20;
pub const CA_NOTICE: &str = "the CA certificate changed: agents must reload it (sg ca export)";

pub struct Created {
    pub secret: SecretMeta,
    pub rules: Vec<Rule>,
    pub ca_changed: bool,
}

/// Recomputes the CA domains from the rules visible on `conn` and persists them there.
fn plan_ca(ca: &CaService, conn: &Connection) -> ApiResult<Option<PreparedCa>> {
    let mut domains = derive_ca_domains(&list_rules_in(conn, None)?);
    // Rows stored before hosts were checked against the CA's rules may hold hosts it cannot accept. Skipping
    // them only narrows the CA (those hosts cannot be intercepted), so it fails closed and startup survives.
    let skipped: Vec<String> = domains
        .iter()
        .filter(|d| !ca.domain_is_acceptable(d))
        .cloned()
        .collect();
    if !skipped.is_empty() {
        tracing::warn!(
            hosts = %skipped.join(", "),
            "rule hosts the CA cannot accept were left out of its permitted domains"
        );
        domains.retain(|d| ca.domain_is_acceptable(d));
    }
    let prepared = ca.prepare_domains(&domains)?;
    if let Some(p) = &prepared {
        ca.persist(conn, p)?;
    }
    Ok(prepared)
}

/// Installs the prepared CA (call only after the transaction committed). Returns whether the CA changed.
fn install(ca: &CaService, prepared: Option<PreparedCa>) -> bool {
    prepared.map(|p| ca.install(p)).is_some()
}

/// Makes the CA's permitted domains exactly the ones derived from the stored rules. Returns whether
/// the CA certificate changed. Used by `sg serve` at startup.
pub fn sync_ca(vault: &Vault, ca: &CaService) -> ApiResult<bool> {
    let _guard = ca.domain_guard();
    let prepared = vault.in_transaction(|conn| plan_ca(ca, conn))?;
    Ok(install(ca, prepared))
}

pub fn create_secret(
    s: &AppState,
    name: &str,
    value: &str,
    specs: Vec<RuleSpec>,
) -> ApiResult<Created> {
    if specs.is_empty() {
        return Err(ApiError::bad_request(
            "a secret needs at least one rule: say which role, host and header or parameter it is injected into",
        ));
    }
    if specs.len() > MAX_RULES_PER_SECRET {
        return Err(ApiError::bad_request(
            "too many rules for one secret (max 20)",
        ));
    }
    let _guard = s.ca.domain_guard();
    let mut rules = Vec::new();
    let mut prepared = None;
    let secret = s.vault.add_secret_with(name, value, |conn, meta| {
        for spec in specs {
            rules.push(insert_rule_in(conn, spec.with_secret(meta.id))?);
        }
        prepared = plan_ca(&s.ca, conn)?;
        Ok::<(), ApiError>(())
    })?;
    Ok(Created {
        secret,
        rules,
        ca_changed: install(&s.ca, prepared),
    })
}

pub fn add_rule(s: &AppState, rule: NewRule) -> ApiResult<(Rule, bool)> {
    let _guard = s.ca.domain_guard();
    let (rule, prepared) = s.vault.in_transaction(|conn| {
        let rule = insert_rule_in(conn, rule)?;
        Ok::<_, ApiError>((rule, plan_ca(&s.ca, conn)?))
    })?;
    Ok((rule, install(&s.ca, prepared)))
}

pub fn delete_rule(s: &AppState, id: i64) -> ApiResult<()> {
    let _guard = s.ca.domain_guard();
    let prepared = s.vault.in_transaction(|conn| {
        let secret_id = sg_policy::secret_of_rule_in(conn, id)?;
        if sg_policy::rule_count_for_secret_in(conn, secret_id)? <= 1 {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "this is the last rule of its secret: delete the secret instead, or add another rule first"
                    .into(),
            ));
        }
        sg_policy::remove_rule_in(conn, id)?;
        plan_ca(&s.ca, conn)
    })?;
    install(&s.ca, prepared);
    Ok(())
}

pub fn delete_secret(s: &AppState, name: &str) -> ApiResult<()> {
    let _guard = s.ca.domain_guard();
    let mut prepared = None;
    s.vault.remove_secret_cascade_with(name, |conn| {
        prepared = plan_ca(&s.ca, conn)?;
        Ok::<(), ApiError>(())
    })?;
    install(&s.ca, prepared);
    Ok(())
}

pub fn delete_role(s: &AppState, name: &str) -> ApiResult<()> {
    let _guard = s.ca.domain_guard();
    let prepared = s.vault.in_transaction(|conn| {
        let orphans = sg_policy::secrets_orphaned_by_role_in(conn, name)?;
        if !orphans.is_empty() {
            let shown: Vec<&str> = orphans.iter().take(5).map(String::as_str).collect();
            let more = orphans.len().saturating_sub(5);
            return Err(ApiError(
                StatusCode::CONFLICT,
                format!(
                    "deleting this role would leave secrets without rules: {}{}; delete them or give them rules for another role first",
                    shown.join(", "),
                    if more > 0 {
                        format!(" and {more} more")
                    } else {
                        String::new()
                    }
                ),
            ));
        }
        sg_policy::remove_role_in(conn, name)?;
        plan_ca(&s.ca, conn)
    })?;
    install(&s.ca, prepared);
    Ok(())
}
