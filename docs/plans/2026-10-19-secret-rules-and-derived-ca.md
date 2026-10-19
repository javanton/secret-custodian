# Secretos con reglas obligatorias y CA derivada: plan de implementación

> **Estado:** ejecutado el 2026-10-19 (ver commits de la rama).

> **Para agentes:** SUB-SKILL requerida: `superpowers:subagent-driven-development` (recomendada) o
> `superpowers:executing-plans`. Los pasos usan casillas `- [ ]`. Antes de empezar, cargar el entorno de Rust:
> `source ~/.cargo/env` en **cada** llamada de Bash.

**Objetivo:** que todo secreto nazca con al menos una regla (operación atómica) y que las name constraints de la CA
se deriven de los hosts de las reglas, sin pasos manuales (`sg ca allow-domain` desaparece).

**Arquitectura:** el núcleo (`sg-core`) ofrece transacciones con *hook* para que una operación de varias tablas sea
atómica; `sg-policy` expone sus operaciones sobre `&Connection` para poder ejecutarse dentro de esas transacciones;
`sg-ca` separa *preparar* (validar y firmar, sin efectos), *persistir* (dentro de la transacción) e *instalar* (en
memoria, tras el commit). `sg-admin` orquesta todo en un módulo `ops` y expone la API nueva. La CLI y la web se
adaptan al contrato nuevo.

**Stack:** Rust (tokio, axum, rusqlite, rcgen), clap, JS sin build (tests con `node --test` y un DOM falso).

**Spec:** `docs/specs/2026-10-16-secret-guardian-vault.md`, en especial §6.3, §7.3–7.5 (enmienda 2026-10-19).

**Rama:** se continúa en `feature/phase1-core` (aún sin integrar; una rama apilada no aportaría nada).

## Restricciones globales

- Nunca se devuelve ni se registra el valor de un secreto: ni en respuestas, ni en errores, ni en logs (la CLI sigue
  redactando el valor en los mensajes de error).
- Los mensajes de error de la API son estáticos y aptos para el cliente; los detalles internos solo van al log.
- Toda escritura de la API sigue exigiendo `Content-Type: application/json` y cuerpo ≤ 64 KiB.
- `reveal_for_injection` solo lo llama el proxy (hay un test que escanea las fuentes del admin).
- Commits Conventional Commits `type(scope): subject`, uno por tarea, terminados con
  `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Test altitude: por tarea solo los tests del crate/fichero tocado; el workspace completo **una vez** en la Tarea 7.
- Linux únicamente; sin dependencias nuevas.

## Foco de revisión

Entradas o condiciones que la spec implica pero que ninguna tarea cubriría por sí sola; cada una tiene su test en la
tarea que indica.

1. **Host que la CA rechaza** (p. ej. `x.invalid`): la creación falla con 400 y no queda secreto, regla ni cambio en
   la CA (Tarea 4).
2. **Dos altas simultáneas con hosts distintos**: ambos dominios acaban en la CA; no se pierde ninguno (Tarea 4).
3. **Borrar el último host de la CA** (última regla, secreto o rol que lo usaba): vuelve el placeholder `invalid`
   (Tarea 3 y 4).
4. **Borrar un rol que dejaría secretos sin reglas**: 409 con los nombres afectados; no se borra nada (Tarea 4).
5. **Base de datos previa** con reglas cuyos hosts la CA no permitía (o dominios manuales sin reglas): el arranque
   sincroniza una vez y el resultado queda estable en el segundo arranque (Tarea 4).
6. **Valor del secreto en errores**: una alta con regla inválida no refleja el valor en la respuesta (Tarea 4 y 5).
7. **Comodín** `*.x` → dominio `x`, sin duplicados cuando coexiste con `x` (Tarea 2).

## Estructura de ficheros

| Fichero | Cambio |
|---|---|
| `crates/core/src/vault.rs` | `Vault::in_transaction` |
| `crates/core/src/secrets.rs` | `add_secret_with`, `remove_secret_cascade_with`, `list_secrets_with_rule_counts` |
| `crates/policy/src/model.rs` | `RuleSpec` |
| `crates/policy/src/store.rs` | funciones `*_in(&Connection)`; los envoltorios con `&Vault` se mantienen |
| `crates/policy/src/domains.rs` (nuevo) | `derive_ca_domains` |
| `crates/ca/src/service.rs` | `PreparedCa`, `prepare_domains`, `persist`, `install`; `allow_domain` las reutiliza |
| `crates/admin/src/ops.rs` (nuevo) | operaciones atómicas + sincronización de la CA |
| `crates/admin/src/api.rs` | handlers nuevos; se elimina `/ca/domains` |
| `crates/sg/src/serve.rs` | sincronización al arrancar |
| `crates/cli/src/{commands,input}.rs` | `secret add` con regla; se elimina `ca allow-domain` |
| `web/app.js`, `web/style.css` | alta de secreto con reglas; CA solo lectura |
| `scripts/e2e*.sh`, tests | adaptados al contrato nuevo |
| `docs/*`, `README.md` | actualizados |

---

### Tarea 1: primitivas transaccionales del núcleo

**Archivos:**
- Modificar: `crates/core/src/vault.rs`, `crates/core/src/secrets.rs`

**Interfaces:**
- Produce (las usan las tareas 4 y 7):
  - `Vault::in_transaction<T, E, F>(&self, f: F) -> Result<T, E>` con `E: From<CoreError>`,
    `F: FnOnce(&Connection) -> Result<T, E>`: abre transacción, ejecuta `f`, hace commit si `Ok`, revierte si `Err`.
  - `Vault::add_secret_with<E, F>(&self, name: &str, value: &str, extra: F) -> Result<SecretMeta, E>` con
    `F: FnOnce(&Connection, &SecretMeta) -> Result<(), E>`: inserta el secreto y ejecuta `extra` en la misma transacción.
  - `Vault::remove_secret_cascade_with<E, F>(&self, name: &str, after: F) -> Result<(), E>` con
    `F: FnOnce(&Connection) -> Result<(), E>`: borra las reglas del secreto, el secreto y ejecuta `after`, todo atómico.
  - `Vault::list_secrets_with_rule_counts(&self) -> Result<Vec<(SecretMeta, i64)>, CoreError>`.
  - `remove_secret` y `add_secret` no cambian de comportamiento (siguen siendo la API de biblioteca: `remove_secret`
    sigue devolviendo `InUse` si hay reglas).

- [x] **Paso 1: enmendar la spec** (regla 8: hueco detectado al planificar). Hecho al escribir este plan: §7.5
  recoge que borrar un rol que dejaría secretos sin reglas responde `409`.

- [x] **Paso 2: tests que fallan** (en `mod tests` de `crates/core/src/secrets.rs`, que ya tiene el helper `vault()`):

```rust
    fn seed_rule(v: &Vault, secret_id: i64) {
        let c = v.conn();
        c.execute("INSERT OR IGNORE INTO roles (name, unmatched_policy) VALUES ('r','deny')", []).unwrap();
        c.execute(
            "INSERT INTO rules (role, host_pattern, path_pattern, methods, injection_kind, target_name, template, secret_id)
             VALUES ('r','h.com','*','','header','X-K','{secret}',?1)",
            [secret_id],
        )
        .unwrap();
    }

    #[test]
    fn add_secret_with_rolls_the_secret_back_when_the_hook_fails() {
        let (_d, v) = vault();
        let r: Result<SecretMeta, CoreError> =
            v.add_secret_with("a", "x", |_, _| Err(CoreError::InUse));
        assert!(matches!(r, Err(CoreError::InUse)));
        assert!(v.list_secrets().unwrap().is_empty());
    }

    #[test]
    fn add_secret_with_runs_the_hook_in_the_same_transaction() {
        let (_d, v) = vault();
        let meta = v
            .add_secret_with("a", "x", |conn, m| {
                conn.execute("INSERT INTO roles (name, unmatched_policy) VALUES ('r','deny')", [])?;
                assert!(m.id > 0);
                Ok::<(), CoreError>(())
            })
            .unwrap();
        assert_eq!(meta.name, "a");
        assert_eq!(v.conn().query_row("SELECT COUNT(*) FROM roles", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
    }

    #[test]
    fn cascade_removal_deletes_rules_and_runs_the_hook_atomically() {
        let (_d, v) = vault();
        let meta = v.add_secret("a", "x").unwrap();
        seed_rule(&v, meta.id);
        assert!(matches!(v.remove_secret("a"), Err(CoreError::InUse)));
        // a failing hook leaves both the secret and its rule in place
        let r: Result<(), CoreError> = v.remove_secret_cascade_with("a", |_| Err(CoreError::Crypto));
        assert!(matches!(r, Err(CoreError::Crypto)));
        assert_eq!(v.list_secrets().unwrap().len(), 1);
        assert_eq!(v.conn().query_row("SELECT COUNT(*) FROM rules", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        // success removes both
        v.remove_secret_cascade_with("a", |_| Ok::<(), CoreError>(())).unwrap();
        assert!(v.list_secrets().unwrap().is_empty());
        assert_eq!(v.conn().query_row("SELECT COUNT(*) FROM rules", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }

    #[test]
    fn rule_counts_are_reported_per_secret() {
        let (_d, v) = vault();
        let a = v.add_secret("a", "x").unwrap();
        v.add_secret("b", "x").unwrap();
        seed_rule(&v, a.id);
        let counts: Vec<(String, i64)> = v
            .list_secrets_with_rule_counts()
            .unwrap()
            .into_iter()
            .map(|(m, n)| (m.name, n))
            .collect();
        assert_eq!(counts, vec![("a".to_string(), 1), ("b".to_string(), 0)]);
    }

    #[test]
    fn in_transaction_commits_on_ok_and_rolls_back_on_err() {
        let (_d, v) = vault();
        let ok: Result<(), CoreError> = v.in_transaction(|c| {
            c.execute("INSERT INTO roles (name, unmatched_policy) VALUES ('keep','deny')", [])?;
            Ok(())
        });
        ok.unwrap();
        let err: Result<(), CoreError> = v.in_transaction(|c| {
            c.execute("INSERT INTO roles (name, unmatched_policy) VALUES ('drop','deny')", [])?;
            Err(CoreError::Crypto)
        });
        assert!(err.is_err());
        let names: Vec<String> = {
            let c = v.conn();
            let mut st = c.prepare("SELECT name FROM roles").unwrap();
            st.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
        };
        assert_eq!(names, vec!["keep".to_string()]);
    }
```

- [x] **Paso 3: ver que falla.** `cargo test -p sg-core --lib secrets` → error de compilación (métodos inexistentes).

- [x] **Paso 4: implementar.** En `crates/core/src/vault.rs`, junto a `conn()`:

```rust
    /// Runs `f` in one transaction: committed when it returns `Ok`, rolled back on `Err`. The
    /// connection stays locked for the whole call, so concurrent writers are serialized.
    pub fn in_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<CoreError>,
        F: FnOnce(&Connection) -> Result<T, E>,
    {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(CoreError::from)?;
        let out = f(&tx)?;
        tx.commit().map_err(CoreError::from)?;
        Ok(out)
    }
```

  (importar `CoreError` si hace falta). En `crates/core/src/secrets.rs`: extraer el cuerpo de inserción a una función
  libre y reescribir `add_secret` sobre `add_secret_with`:

```rust
fn insert_secret(vault: &Vault, conn: &Connection, name: &str, value: &str) -> Result<SecretMeta, CoreError> {
    let exists: bool = conn.query_row("SELECT COUNT(*) FROM secrets WHERE name = ?1", [name], |r| r.get::<_, i64>(0))? > 0;
    if exists {
        return Err(CoreError::AlreadyExists);
    }
    let ts = now();
    conn.execute("INSERT INTO secrets (name, value_enc, created_at) VALUES (?1, x'', ?2)", params![name, ts])?;
    let id = conn.last_insert_rowid();
    conn.execute(
        "UPDATE secrets SET value_enc = ?1 WHERE id = ?2",
        params![vault.seal_value(&aad(id), value.as_bytes()), id],
    )?;
    Ok(SecretMeta { id, name: name.into(), created_at: ts, rotated_at: None })
}

impl Vault {
    pub fn add_secret(&self, name: &str, value: &str) -> Result<SecretMeta, CoreError> {
        self.add_secret_with(name, value, |_, _| Ok::<(), CoreError>(()))
    }

    /// Inserts the secret and runs `extra` in the same transaction; an `Err` from it rolls everything back.
    pub fn add_secret_with<E, F>(&self, name: &str, value: &str, extra: F) -> Result<SecretMeta, E>
    where
        E: From<CoreError>,
        F: FnOnce(&Connection, &SecretMeta) -> Result<(), E>,
    {
        validate_name(name)?;
        validate_secret_value(value)?;
        self.in_transaction(|tx| {
            let meta = insert_secret(self, tx, name, value)?;
            extra(tx, &meta)?;
            Ok(meta)
        })
    }

    /// Deletes the secret together with its rules, then runs `after`, all in one transaction.
    pub fn remove_secret_cascade_with<E, F>(&self, name: &str, after: F) -> Result<(), E>
    where
        E: From<CoreError>,
        F: FnOnce(&Connection) -> Result<(), E>,
    {
        self.in_transaction(|tx| {
            let meta = lookup(tx, name)?;
            tx.execute("DELETE FROM rules WHERE secret_id = ?1", [meta.id]).map_err(CoreError::from)?;
            delete_by_id(tx, meta.id)?;
            after(tx)
        })
    }

    pub fn list_secrets_with_rule_counts(&self) -> Result<Vec<(SecretMeta, i64)>, CoreError> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT s.id, s.name, s.created_at, s.rotated_at,
                    (SELECT COUNT(*) FROM rules r WHERE r.secret_id = s.id)
             FROM secrets s ORDER BY s.name",
        )?;
        let rows = st
            .query_map([], |r| Ok((row_meta(r)?, r.get::<_, i64>(4)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
```

  (en `add_secret_with` los `?` sobre `validate_*` y `insert_secret` convierten `CoreError` → `E` con `From`.
  Borrar la implementación anterior de `add_secret`.)

- [x] **Paso 5: ver que pasa.** `cargo test -p sg-core` → todo en verde (incluye los tests previos de `vault.rs`).
- [x] **Paso 6: commit.** `feat(core): transactional hooks for secrets and rules`.

---

### Tarea 2: política sobre `&Connection` y derivación de dominios

**Archivos:**
- Modificar: `crates/policy/src/model.rs`, `crates/policy/src/store.rs`, `crates/policy/src/lib.rs`
- Crear: `crates/policy/src/domains.rs`
- Test: `crates/policy/tests/conn_api.rs` (nuevo) y `mod tests` en `domains.rs`

**Interfaces:**
- Consume: nada nuevo de la Tarea 1 (solo `sg_core::Vault::conn`).
- Produce:
  - `pub struct RuleSpec { role: String, host_pattern: String, path_pattern: String, methods: Vec<String>, kind: InjectionKind, target_name: String, template: String }` (campos públicos, `Debug, Clone`) con `fn with_secret(self, secret_id: i64) -> NewRule`.
  - `get_role_in`, `insert_rule_in`, `list_rules_in`, `remove_rule_in`, `remove_role_in`,
    `rule_count_for_secret_in(conn, secret_id) -> Result<i64, PolicyError>`,
    `secret_of_rule_in(conn, rule_id) -> Result<i64, PolicyError>` (`NotFound` si no existe),
    `secrets_orphaned_by_role_in(conn, role) -> Result<Vec<String>, PolicyError>`: todos con `conn: &rusqlite::Connection`.
  - `derive_ca_domains(rules: &[Rule]) -> Vec<String>`: hosts sin `*.`, ordenados y sin duplicados.
  - Los envoltorios actuales (`add_rule`, `list_rules`, `remove_rule`, `get_role`, `remove_role`) conservan firma.

- [x] **Paso 1: tests que fallan.** `crates/policy/src/domains.rs`:

```rust
use crate::model::Rule;

/// Domains the CA must permit: the host of every rule (`*.x` becomes `x`, which also covers
/// subdomains), sorted and without duplicates.
pub fn derive_ca_domains(rules: &[Rule]) -> Vec<String> {
    let mut d: Vec<String> = rules
        .iter()
        .map(|r| r.host_pattern.strip_prefix("*.").unwrap_or(&r.host_pattern).to_string())
        .collect();
    d.sort();
    d.dedup();
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InjectionKind;

    fn rule(host: &str) -> Rule {
        Rule {
            id: 1, role: "r".into(), host_pattern: host.into(), path_pattern: "*".into(), methods: vec![],
            kind: InjectionKind::Header, target_name: "X".into(), template: "{secret}".into(), secret_id: 1,
        }
    }

    #[test]
    fn wildcards_collapse_into_their_domain_without_duplicates() {
        let rules = [rule("*.habbi.cc"), rule("habbi.cc"), rule("api.github.com"), rule("api.github.com")];
        assert_eq!(derive_ca_domains(&rules), vec!["api.github.com", "habbi.cc"]);
        assert!(derive_ca_domains(&[]).is_empty());
    }
}
```

  `crates/policy/tests/conn_api.rs`:

```rust
use sg_core::{crypto, KeyInput, Vault};
use sg_policy::*;

fn vault() -> (tempfile::TempDir, Vault) {
    let d = tempfile::tempdir().unwrap();
    let v = Vault::init(&d.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap();
    (d, v)
}

fn spec(role: &str, host: &str) -> RuleSpec {
    RuleSpec {
        role: role.into(), host_pattern: host.into(), path_pattern: "*".into(), methods: vec![],
        kind: InjectionKind::Header, target_name: "Authorization".into(), template: "Bearer {secret}".into(),
    }
}

#[test]
fn conn_functions_cover_count_owner_and_orphans() {
    let (_d, v) = vault();
    add_role(&v, "dev", Unmatched::Deny).unwrap();
    add_role(&v, "rev", Unmatched::Deny).unwrap();
    let only_dev = v.add_secret("only-dev", "x").unwrap();
    let both = v.add_secret("both", "x").unwrap();
    let conn = v.conn();
    let r1 = insert_rule_in(&conn, spec("dev", "a.com").with_secret(only_dev.id)).unwrap();
    insert_rule_in(&conn, spec("dev", "b.com").with_secret(both.id)).unwrap();
    insert_rule_in(&conn, spec("rev", "b.com").with_secret(both.id)).unwrap();
    assert_eq!(rule_count_for_secret_in(&conn, both.id).unwrap(), 2);
    assert_eq!(secret_of_rule_in(&conn, r1.id).unwrap(), only_dev.id);
    assert!(matches!(secret_of_rule_in(&conn, 9999), Err(PolicyError::NotFound)));
    // removing role `dev` would leave `only-dev` without rules, but not `both`
    assert_eq!(secrets_orphaned_by_role_in(&conn, "dev").unwrap(), vec!["only-dev".to_string()]);
    assert!(secrets_orphaned_by_role_in(&conn, "rev").unwrap().is_empty());
    assert_eq!(list_rules_in(&conn, Some("dev")).unwrap().len(), 2);
    remove_rule_in(&conn, r1.id).unwrap();
    assert!(matches!(remove_rule_in(&conn, r1.id), Err(PolicyError::NotFound)));
    remove_role_in(&conn, "rev").unwrap();
    assert!(get_role_in(&conn, "rev").unwrap().is_none());
}

#[test]
fn insert_rule_in_still_validates() {
    let (_d, v) = vault();
    add_role(&v, "dev", Unmatched::Deny).unwrap();
    let s = v.add_secret("s", "x").unwrap();
    let conn = v.conn();
    assert!(matches!(
        insert_rule_in(&conn, spec("dev", "*.com").with_secret(s.id)),
        Err(PolicyError::Invalid(_))
    ));
    assert!(matches!(
        insert_rule_in(&conn, spec("ghost", "a.com").with_secret(s.id)),
        Err(PolicyError::Invalid("unknown role"))
    ));
}
```

- [x] **Paso 2: ver que falla.** `cargo test -p sg-policy` → error de compilación.
- [x] **Paso 3: implementar.**
  - `model.rs`: añadir `RuleSpec` (campos públicos) y
    `impl RuleSpec { pub fn with_secret(self, secret_id: i64) -> NewRule { NewRule { role: self.role, host_pattern: self.host_pattern, path_pattern: self.path_pattern, methods: self.methods, kind: self.kind, target_name: self.target_name, template: self.template, secret_id } } }`.
  - `store.rs`: cambiar `fn validate(v: &Vault, r)` por `fn validate(conn: &Connection, r)`, usando `get_role_in(conn, ..)` y
    `conn.query_row("SELECT COUNT(*) FROM secrets WHERE id = ?1", ...)`. Renombrar los cuerpos actuales a las
    variantes `*_in(conn: &Connection, ..)` (`get_role_in`, `insert_rule_in` = cuerpo de `add_rule` sin el `validate(v, ..)` separado: llama a `validate(conn, &r)?` y hace el `INSERT`; `list_rules_in`, `remove_rule_in`, `remove_role_in`) y dejar los públicos
    antiguos como envoltorios de una línea: `pub fn add_rule(v, r) { insert_rule_in(&v.conn(), r) }`,
    `list_rules(v, role) { list_rules_in(&v.conn(), role) }`, etc. Añadir:

```rust
pub fn rule_count_for_secret_in(conn: &Connection, secret_id: i64) -> Result<i64, PolicyError> {
    Ok(conn.query_row("SELECT COUNT(*) FROM rules WHERE secret_id = ?1", [secret_id], |r| r.get(0))?)
}

pub fn secret_of_rule_in(conn: &Connection, rule_id: i64) -> Result<i64, PolicyError> {
    conn.query_row("SELECT secret_id FROM rules WHERE id = ?1", [rule_id], |r| r.get(0))
        .optional()?
        .ok_or(PolicyError::NotFound)
}

/// Names of the secrets whose every rule belongs to `role`: deleting the role would orphan them.
pub fn secrets_orphaned_by_role_in(conn: &Connection, role: &str) -> Result<Vec<String>, PolicyError> {
    let mut st = conn.prepare(
        "SELECT s.name FROM secrets s
         WHERE EXISTS (SELECT 1 FROM rules r WHERE r.secret_id = s.id AND r.role = ?1)
           AND NOT EXISTS (SELECT 1 FROM rules r WHERE r.secret_id = s.id AND r.role <> ?1)
         ORDER BY s.name",
    )?;
    let rows = st.query_map([role], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
    Ok(rows)
}
```

  - `lib.rs`: `mod domains;` y `pub use domains::derive_ca_domains;`. `use rusqlite::{params, Connection, OptionalExtension};` en `store.rs`; añadir `rusqlite` a las dependencias de `crates/policy/Cargo.toml` solo si aún no es dependencia directa (ya lo usa `store.rs`, así que lo es).
- [x] **Paso 4: ver que pasa.** `cargo test -p sg-policy` (incluye los tests previos; 1 ignorado como siempre) y `cargo clippy -p sg-policy --all-targets -- -D warnings`.
- [x] **Paso 5: commit.** `refactor(policy): rule operations on a connection and CA domain derivation`.

---

### Tarea 3: la CA se prepara, se persiste y se instala por separado

**Archivos:**
- Modificar: `crates/ca/src/service.rs`, `crates/ca/src/lib.rs` (re-exportar `PreparedCa`)
- Test: `crates/ca/tests/ca.rs` (usa el helper `ca()` y `handshake()` ya existentes)

**Interfaces:**
- Consume: `Vault::in_transaction` (Tarea 1) solo en los tests.
- Produce:
  - `pub struct PreparedCa` (opaco).
  - `CaService::prepare_domains(&self, domains: &[String]) -> Result<Option<PreparedCa>, CaError>`: normaliza
    (trim, minúsculas, ordena, quita duplicados), valida cada dominio con `validate_domain`, devuelve `None` si el
    conjunto no cambia y, si cambia, firma el certificado nuevo y lo sondea con `probe`. **No toma el lock de
    estado más allá de una lectura breve y no escribe nada.**
  - `CaService::persist(&self, conn: &rusqlite::Connection, p: &PreparedCa) -> Result<(), CaError>`: `UPDATE ca`.
  - `CaService::install(&self, p: PreparedCa)`: sustituye el estado en memoria y vacía la caché de hojas.
  - `allow_domain` se reescribe sobre estas tres (sin anidar locks) y mantiene su comportamiento y errores.

- [x] **Paso 1: tests que fallan** (añadir a `crates/ca/tests/ca.rs`):

```rust
fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|d| d.to_string()).collect()
}

#[test]
fn prepare_has_no_effect_until_persisted_and_installed() {
    let (_d, v, ca) = ca();
    let p = ca.prepare_domains(&s(&["b.com", "a.com", "a.com"])).unwrap().unwrap();
    assert!(ca.domains().is_empty(), "nothing changes while only prepared");
    ca.persist(&v.conn(), &p).unwrap();
    ca.install(p);
    assert_eq!(ca.domains(), s(&["a.com", "b.com"]));
    assert!(ca.is_host_permitted("x.a.com"));
    // the same set again is a no-op
    assert!(ca.prepare_domains(&s(&["a.com", "b.com"])).unwrap().is_none());
}

#[test]
fn rejected_domains_leave_the_ca_untouched() {
    let (_d, _v, ca) = ca();
    for bad in ["com", "x.invalid", "1.2.3.4", "UPPER case"] {
        assert!(matches!(ca.prepare_domains(&s(&["ok.com", bad])), Err(CaError::DomainRejected(_))), "{bad}");
    }
    assert!(ca.domains().is_empty());
}

#[test]
fn persist_inside_a_rolled_back_transaction_is_not_kept() {
    let (_d, v, ca) = ca();
    let p = ca.prepare_domains(&s(&["a.com"])).unwrap().unwrap();
    let r: Result<(), CaError> = v.in_transaction(|c| {
        ca.persist(c, &p)?;
        Err(CaError::NotPermitted)
    });
    assert!(r.is_err());
    // a restart sees the old (empty) state
    assert!(CaService::init_or_load(v.clone()).unwrap().domains().is_empty());
}

#[tokio::test]
async fn domains_can_be_removed_and_the_ca_returns_to_the_placeholder() {
    let (_d, v, ca) = ca();
    let p = ca.prepare_domains(&s(&["a.com"])).unwrap().unwrap();
    ca.persist(&v.conn(), &p).unwrap();
    ca.install(p);
    handshake(&ca, "a.com").await.unwrap();
    let p = ca.prepare_domains(&[]).unwrap().unwrap();
    ca.persist(&v.conn(), &p).unwrap();
    ca.install(p);
    assert!(ca.domains().is_empty());
    assert!(handshake(&ca, "a.com").await.is_err());
    assert!(CaService::init_or_load(v.clone()).unwrap().domains().is_empty());
}
```

  `CaError` debe implementar `From<sg_core::CoreError>` para el test `persist_inside…` (`in_transaction` exige
  `E: From<CoreError>`). Si no existe, añadir `#[error(transparent)] Core(#[from] sg_core::CoreError)` a `CaError`
  (grep `enum CaError`); si ya existe una variante equivalente, usarla.

- [x] **Paso 2: ver que falla.** `cargo test -p sg-ca --test ca prepare` → no compila.
- [x] **Paso 3: implementar** en `service.rs`:

```rust
/// A re-issued CA certificate that is validated but not yet persisted or installed.
pub struct PreparedCa {
    cert: rcgen::Certificate,
    domains: Vec<String>,
}

impl CaService {
    pub fn prepare_domains(&self, domains: &[String]) -> Result<Option<PreparedCa>, CaError> {
        let mut domains: Vec<String> = domains.iter().map(|d| d.trim().to_ascii_lowercase()).collect();
        domains.sort();
        domains.dedup();
        for d in &domains {
            validate_domain(d)?;
        }
        if lock(&self.state).domains == domains {
            return Ok(None);
        }
        let cert = ca_params(&domains)?.self_signed(&self.key).map_err(tls)?;
        self.ca_cert_builds.fetch_add(1, Ordering::SeqCst);
        self.probe(&cert, &domains)?;
        Ok(Some(PreparedCa { cert, domains }))
    }

    pub fn persist(&self, conn: &rusqlite::Connection, p: &PreparedCa) -> Result<(), CaError> {
        conn.execute(
            "UPDATE ca SET cert_pem = ?1, domains = ?2 WHERE id = 1",
            rusqlite::params![p.cert.pem(), serde_json::to_string(&p.domains).map_err(tls)?],
        )?;
        Ok(())
    }

    pub fn install(&self, p: PreparedCa) {
        *lock(&self.state) = State { cert_pem: p.cert.pem(), domains: p.domains, signer: Arc::new(p.cert) };
        lock(&self.cache).clear();
    }

    pub fn allow_domain(&self, domain: &str) -> Result<(), CaError> {
        let mut domains = self.domains();
        domains.push(domain.to_string());
        if let Some(p) = self.prepare_domains(&domains)? {
            self.persist(&self.vault.conn(), &p)?;
            self.install(p);
        }
        Ok(())
    }
}
```

  Borrar el `allow_domain` anterior (el de la línea ~235) y actualizar el comentario de la cabecera: «el orden de locks es
  siempre conexión → estado → caché; `prepare_domains` solo lee el estado un instante». Re-exportar `PreparedCa` en
  `lib.rs`.
- [x] **Paso 4: ver que pasa.** `cargo test -p sg-ca` completo (los tests antiguos de `allow_domain` deben seguir en
  verde: es la prueba de que la reescritura no cambió el comportamiento) y clippy del crate.
- [x] **Paso 5: commit.** `feat(ca): prepare, persist and install CA domain sets separately`.

---

### Tarea 4: operaciones atómicas en el admin, API nueva y sincronización al arrancar

**Archivos:**
- Crear: `crates/admin/src/ops.rs`
- Modificar: `crates/admin/src/{lib,api,error}.rs`, `crates/sg/src/serve.rs`
- Test: `crates/admin/tests/api.rs` (nuevos y adaptados), `crates/sg/tests/` si el arranque necesita cobertura

**Interfaces:**
- Consume: Tareas 1–3.
- Produce (contrato HTTP; la CLI y la web de las tareas 5–6 dependen de él):
  - `POST /secrets` ← `{name, value, rules: [{role, host_pattern, path_pattern?="*", methods?=[], kind, target_name, template}, ...]}`
    → `201 {"secret": SecretMeta, "rules": [Rule], "ca_changed": bool, "notice": string|null}`. `400` sin reglas, con más de
    20, o con cualquier regla inválida (incluido host rechazado por la CA); no se crea nada.
  - `GET /secrets` → lista de `SecretMeta` + campo `"rules": <número>`.
  - `POST /rules` (sin cambios de entrada: sigue con `secret_id`) → `201 {"rule": Rule, "ca_changed": bool, "notice": string|null}`
    (desaparece `ca_warning`).
  - `DELETE /rules/{id}` → `204`; `409` si es la última regla de su secreto.
  - `DELETE /secrets/{name}` → `204`; borra sus reglas y resincroniza la CA (ya no devuelve `409`).
  - `DELETE /roles/{name}` → `204`; `409` si dejaría secretos sin reglas (lista hasta 5 nombres); resincroniza la CA.
  - Se elimina `POST /ca/domains` (pasa a 404). `GET /ca` y `GET /ca/cert` no cambian.
  - `sg_admin::ops::sync_ca(vault: &Vault, ca: &CaService) -> ApiResult<bool>` (pública, la usa `sg serve`).

- [x] **Paso 1: tests que fallan.** En `crates/admin/tests/api.rs`, añadir helpers y tests nuevos (los existentes
  se adaptan en el paso 4):

```rust
fn secret_body(name: &str, role: &str, host: &str) -> Value {
    json!({"name": name, "value": "v", "rules": [{
        "role": role, "host_pattern": host, "kind": "header",
        "target_name": "Authorization", "template": "Bearer {secret}"
    }]})
}

async fn role(app: &Router, name: &str) {
    assert_eq!(
        call(app, "POST", "/roles", Some(json!({"name": name, "unmatched": "deny"}))).await.0,
        StatusCode::CREATED
    );
}

async fn domains(app: &Router) -> Vec<String> {
    let v = json_of(&call(app, "GET", "/ca", None).await.1);
    v["domains"].as_array().unwrap().iter().map(|d| d.as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn a_secret_without_rules_is_refused_and_nothing_is_created() {
    let (_d, app) = app();
    for body in [json!({"name":"gh","value":"v"}), json!({"name":"gh","value":"v","rules":[]})] {
        let (st, _) = call(&app, "POST", "/secrets", Some(body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
    assert_eq!(call(&app, "GET", "/secrets", None).await.1, "[]");
}

#[tokio::test]
async fn creating_a_secret_stores_its_rules_and_permits_their_hosts() {
    let (_d, app) = app();
    role(&app, "dev").await;
    let (st, body) = call(&app, "POST", "/secrets", Some(secret_body("gh", "dev", "*.habbi.cc"))).await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let v = json_of(&body);
    assert_eq!(v["secret"]["name"], "gh");
    assert_eq!(v["rules"].as_array().unwrap().len(), 1);
    assert_eq!(v["ca_changed"], true);
    assert!(v["notice"].as_str().unwrap().contains("reload"));
    assert_eq!(domains(&app).await, vec!["habbi.cc"]);
    // a second secret on an already permitted host does not change the CA
    let v = json_of(&call(&app, "POST", "/secrets", Some(secret_body("gl", "dev", "git.habbi.cc"))).await.1);
    assert_eq!(v["ca_changed"], true, "git.habbi.cc is a new exact domain");
    let v = json_of(&call(&app, "POST", "/secrets", Some(secret_body("gl2", "dev", "git.habbi.cc"))).await.1);
    assert_eq!(v["ca_changed"], false);
    assert!(v["notice"].is_null());
    let list = json_of(&call(&app, "GET", "/secrets", None).await.1);
    assert!(list.as_array().unwrap().iter().all(|s| s["rules"] == 1));
}

#[tokio::test]
async fn a_host_the_ca_rejects_creates_nothing() {
    let (_d, app) = app();
    role(&app, "dev").await;
    let marker = "SECRET-MARKER-123456";
    let mut body = secret_body("gh", "dev", "x.invalid");
    body["value"] = json!(marker);
    let (st, text) = call(&app, "POST", "/secrets", Some(body)).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(!text.contains(marker), "the value must never be echoed");
    assert_eq!(call(&app, "GET", "/secrets", None).await.1, "[]");
    assert!(domains(&app).await.is_empty());
    assert!(json_of(&call(&app, "GET", "/rules", None).await.1).as_array().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_role_or_invalid_rule_fails_the_whole_creation() {
    let (_d, app) = app();
    let (st, _) = call(&app, "POST", "/secrets", Some(secret_body("gh", "ghost", "a.com"))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(call(&app, "GET", "/secrets", None).await.1, "[]");
}

#[tokio::test]
async fn the_last_rule_of_a_secret_cannot_be_deleted() {
    let (_d, app) = app();
    role(&app, "dev").await;
    let v = json_of(&call(&app, "POST", "/secrets", Some(secret_body("gh", "dev", "a.com"))).await.1);
    let id = v["rules"][0]["id"].as_i64().unwrap();
    let sid = v["secret"]["id"].as_i64().unwrap();
    assert_eq!(call(&app, "DELETE", &format!("/rules/{id}"), None).await.0, StatusCode::CONFLICT);
    // add a second rule on another host, then the first one can go and its domain is retired
    let extra = json!({"role":"dev","host_pattern":"b.com","kind":"header","target_name":"X","template":"{secret}","secret_id":sid});
    let r = json_of(&call(&app, "POST", "/rules", Some(extra)).await.1);
    assert_eq!(r["ca_changed"], true);
    assert_eq!(domains(&app).await, vec!["a.com", "b.com"]);
    assert_eq!(call(&app, "DELETE", &format!("/rules/{id}"), None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(domains(&app).await, vec!["b.com"]);
}

#[tokio::test]
async fn deleting_a_secret_deletes_its_rules_and_retires_its_domains() {
    let (_d, app) = app();
    role(&app, "dev").await;
    call(&app, "POST", "/secrets", Some(secret_body("gh", "dev", "a.com"))).await;
    assert_eq!(call(&app, "DELETE", "/secrets/gh", None).await.0, StatusCode::NO_CONTENT);
    assert!(json_of(&call(&app, "GET", "/rules", None).await.1).as_array().unwrap().is_empty());
    assert!(domains(&app).await.is_empty());
}

#[tokio::test]
async fn deleting_a_role_that_would_orphan_a_secret_is_refused() {
    let (_d, app) = app();
    role(&app, "dev").await;
    role(&app, "rev").await;
    call(&app, "POST", "/secrets", Some(secret_body("only-dev", "dev", "a.com"))).await;
    let (st, body) = call(&app, "DELETE", "/roles/dev", None).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(body.contains("only-dev"));
    assert_eq!(domains(&app).await, vec!["a.com"]);
    // `rev` has no rules, so it can go
    assert_eq!(call(&app, "DELETE", "/roles/rev", None).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_manual_ca_endpoint_is_gone() {
    let (_d, app) = app();
    let (st, _) = call(&app, "POST", "/ca/domains", Some(json!({"domain":"github.com"}))).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_creations_keep_every_domain() {
    let (_d, app) = app();
    role(&app, "dev").await;
    let hosts = ["a.com", "b.com", "c.com", "d.com"];
    let mut tasks = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let app = app.clone();
        let body = secret_body(&format!("s{i}"), "dev", h);
        tasks.push(tokio::spawn(async move { call(&app, "POST", "/secrets", Some(body)).await.0 }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::CREATED);
    }
    assert_eq!(domains(&app).await, vec!["a.com", "b.com", "c.com", "d.com"]);
}
```

  Y en `crates/admin/tests/ops.rs` (nuevo, mismo patrón de `env`/`vault` que `api.rs` pero sin router) el test del
  arranque:

```rust
use sg_admin::ops::sync_ca;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use sg_policy::*;
use std::sync::Arc;

#[test]
fn startup_sync_derives_the_ca_from_existing_rules_and_is_stable() {
    let d = tempfile::tempdir().unwrap();
    let v = Arc::new(Vault::init(&d.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
    let ca = CaService::init_or_load(v.clone()).unwrap();
    ca.allow_domain("stale.example.org").unwrap(); // a manual domain no rule uses
    add_role(&v, "dev", Unmatched::Deny).unwrap();
    let s = v.add_secret("s", "x").unwrap();
    add_rule(&v, RuleSpec {
        role: "dev".into(), host_pattern: "*.habbi.cc".into(), path_pattern: "*".into(), methods: vec![],
        kind: InjectionKind::Header, target_name: "Authorization".into(), template: "{secret}".into(),
    }.with_secret(s.id)).unwrap();
    assert!(sync_ca(&v, &ca).unwrap());
    assert_eq!(ca.domains(), vec!["habbi.cc"]);
    assert!(!sync_ca(&v, &ca).unwrap(), "second run changes nothing");
    assert_eq!(CaService::init_or_load(v.clone()).unwrap().domains(), vec!["habbi.cc"]);
}
```

- [x] **Paso 2: ver que falla.** `cargo test -p sg-admin --test api --test ops` → fallan/no compilan.
- [x] **Paso 3: implementar `crates/admin/src/ops.rs`:**

```rust
//! Multi-step admin operations. Each one runs in a single SQLite transaction together with the CA's
//! derived domain set, so a rule change and the CA it implies either both happen or neither does.
//! The CA certificate is persisted inside the transaction and installed in memory only after commit.

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
    let domains = derive_ca_domains(&list_rules_in(conn, None)?);
    let prepared = ca.prepare_domains(&domains)?;
    if let Some(p) = &prepared {
        ca.persist(conn, p)?;
    }
    Ok(prepared)
}

fn install(ca: &CaService, prepared: Option<PreparedCa>) -> bool {
    prepared.map(|p| ca.install(p)).is_some()
}

pub fn sync_ca(vault: &Vault, ca: &CaService) -> ApiResult<bool> {
    let prepared = vault.in_transaction(|conn| plan_ca(ca, conn))?;
    Ok(install(ca, prepared))
}

pub fn create_secret(s: &AppState, name: &str, value: &str, specs: Vec<RuleSpec>) -> ApiResult<Created> {
    if specs.is_empty() {
        return Err(ApiError::bad_request(
            "a secret needs at least one rule: say which role, host and header or parameter it is injected into",
        ));
    }
    if specs.len() > MAX_RULES_PER_SECRET {
        return Err(ApiError::bad_request("too many rules for one secret (max 20)"));
    }
    let mut rules = Vec::new();
    let mut prepared = None;
    let secret = s.vault.add_secret_with(name, value, |conn, meta| {
        for spec in specs {
            rules.push(insert_rule_in(conn, spec.with_secret(meta.id))?);
        }
        prepared = plan_ca(&s.ca, conn)?;
        Ok::<(), ApiError>(())
    })?;
    Ok(Created { secret, rules, ca_changed: install(&s.ca, prepared) })
}

pub fn add_rule(s: &AppState, rule: NewRule) -> ApiResult<(Rule, bool)> {
    let (rule, prepared) = s.vault.in_transaction(|conn| {
        let rule = insert_rule_in(conn, rule)?;
        Ok::<_, ApiError>((rule, plan_ca(&s.ca, conn)?))
    })?;
    Ok((rule, install(&s.ca, prepared)))
}

pub fn delete_rule(s: &AppState, id: i64) -> ApiResult<()> {
    let prepared = s.vault.in_transaction(|conn| {
        let secret_id = sg_policy::secret_of_rule_in(conn, id)?;
        if sg_policy::rule_count_for_secret_in(conn, secret_id)? <= 1 {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "this is the last rule of its secret: delete the secret instead, or add another rule first".into(),
            ));
        }
        sg_policy::remove_rule_in(conn, id)?;
        plan_ca(&s.ca, conn)
    })?;
    install(&s.ca, prepared);
    Ok(())
}

pub fn delete_secret(s: &AppState, name: &str) -> ApiResult<()> {
    let mut prepared = None;
    s.vault.remove_secret_cascade_with(name, |conn| {
        prepared = plan_ca(&s.ca, conn)?;
        Ok::<(), ApiError>(())
    })?;
    install(&s.ca, prepared);
    Ok(())
}

pub fn delete_role(s: &AppState, name: &str) -> ApiResult<()> {
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
                    if more > 0 { format!(" and {more} more") } else { String::new() }
                ),
            ));
        }
        sg_policy::remove_role_in(conn, name)?;
        plan_ca(&s.ca, conn)
    })?;
    install(&s.ca, prepared);
    Ok(())
}
```

  `lib.rs`: `pub mod ops;`. `error.rs`: añadir `impl From<sg_core::CoreError>` ya existe; asegurar que
  `From<rusqlite::Error>` no hace falta (las funciones de política devuelven `PolicyError`). `api.rs`:
  - `NewSecret` pasa a `{ name, value, rules: Vec<RuleSpecBody> }` (`#[serde(default)]` para que la ausencia dé el
    mensaje de «necesita al menos una regla» y no un error genérico de JSON). `RuleSpecBody` (con
    `deny_unknown_fields`: `role, host_pattern, path_pattern (default "*"), methods (default), kind, target_name,
    template`) + `impl From<RuleSpecBody> for sg_policy::RuleSpec`.
  - `add_secret` llama a `ops::create_secret(&s, &b.name, &b.value, b.rules.into_iter().map(Into::into).collect())`
    y responde `201` con `json!({"secret": c.secret, "rules": c.rules, "ca_changed": c.ca_changed, "notice": c.ca_changed.then_some(ops::CA_NOTICE)})`.
  - `list_secrets` usa `list_secrets_with_rule_counts` y devuelve `Vec<Value>` (`serde_json::to_value(meta)` + `"rules": n`).
  - `add_rule`: usar `ops::add_rule` con el `NewRule` construido igual que hoy; respuesta `{"rule", "ca_changed", "notice"}`.
  - `delete_rule` → `ops::delete_rule`; `delete_secret` → `ops::delete_secret(&s, name_param(&name)?)`;
    `delete_role` → `ops::delete_role`.
  - Eliminar la ruta `/ca/domains` y los structs/handler `AllowDomain`/`ca_allow`.
  - Actualizar el test de escaneo de fuentes si cita `ca_allow` (grep).
  - Eliminar de `error.rs` la rama `InUse` solo si `grep -rn InUse crates/admin` queda vacío tras el cambio; si no, mantenerla.

  `crates/sg/src/serve.rs`, justo después de `CaService::init_or_load(...)`:

```rust
    if sg_admin::ops::sync_ca(&vault, &ca)
        .map_err(|e| anyhow::anyhow!("cannot sync the CA with the rules: {}", e.1))?
    {
        tracing::info!("CA domains re-derived from the rules; agents must reload the CA certificate");
    }
```

- [x] **Paso 4: adaptar los tests existentes** (`crates/admin/tests/api.rs`; ver con
  `grep -n '"/secrets"\|/ca/domains\|ca_warning' crates/admin/tests/api.rs`):
  - Sustituir cada alta `POST /secrets {"name","value"}` por `secret_body(name, role, host)` creando antes el rol con
    `role(&app, ..)`; los `secret_id` que antes valían 1 se obtienen de `v["secret"]["id"]`.
  - `full_policy_flow_and_conflicts`: la primera regla ya no viene de `POST /rules` sino de la alta; sustituir la
    aserción `ca_warning`/`allow-domain` por `ca_changed == true` y el 409 de borrar secreto con regla por el borrado en
    cascada (204).
  - Eliminar `no_ca_warning_once_the_domain_is_allowed` y las llamadas a `/ca/domains` de `ca_endpoints`
    (el 404 ya lo cubre `the_manual_ca_endpoint_is_gone`).
  - `no_route_ever_returns_a_secret_value` y `secret_with_crlf_is_rejected_with_400`: mismo cambio de cuerpo.
  - `deleting_a_role_cascades_its_rules`: ahora el rol de la prueba debe dejar otra regla en otro rol para no huérfanar,
    o cambiar la aserción al 409; ajustar según el test (leerlo antes de editar).
- [x] **Paso 5: ver que pasa.** `cargo test -p sg-admin` completo y `cargo test -p sg --lib` (el arranque compila) +
  clippy de `sg-admin` y `sg`.
- [x] **Paso 6: commit.** `feat(admin): atomic secret creation with rules and CA derived from rules`.

---

### Tarea 5: CLI

**Archivos:**
- Modificar: `crates/cli/src/commands.rs`, `crates/cli/src/input.rs`, `crates/sg/src/main.rs` (texto de ayuda)
- Test: `crates/cli/src/commands.rs` (`mod tests`), `crates/cli/tests/run.rs`, `crates/sg/tests/cli_e2e.rs`

**Interfaces:**
- Consume: contrato HTTP de la Tarea 4.
- Produce: `sg secret add NAME [--role R] --host H [--path P] [--methods M,..] (--header N | --query N) [--template T]`;
  `sg ca` solo `export` y `status`; `sg secret ls` con columna `RULES`; `sg rule add` conserva su sintaxis.
  Con `--role` omitido: un único rol existente se usa; ninguno → se crea `default` (`passthrough`) y se avisa por
  stderr; varios → error que lista los roles.

- [x] **Paso 1: tests que fallan** (en `mod tests` de `commands.rs`, con su helper `parse`):

```rust
    #[test]
    fn secret_add_requires_a_rule_target_and_a_host() {
        assert!(parse(["sg", "secret", "add", "gh"]).is_err());
        assert!(parse(["sg", "secret", "add", "gh", "--host", "a.com"]).is_err());
        assert!(parse(["sg", "secret", "add", "gh", "--host", "a.com", "--header", "Authorization", "--query", "k"]).is_err());
        assert!(parse(["sg", "secret", "add", "gh", "--host", "a.com", "--header", "Authorization"]).is_ok());
        assert!(parse(["sg", "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--query", "k"]).is_ok());
    }

    #[test]
    fn ca_has_no_allow_domain_any_more() {
        assert!(parse(["sg", "ca", "allow-domain", "x.com"]).is_err());
        assert!(parse(["sg", "ca", "status"]).is_ok());
    }
```

  Y en `crates/cli/tests/run.rs` (que usa `fake(...)` y `cli(&f, args, stdin)`), tests del flujo con servidor falso:

```rust
fn secrets_fake(roles: serde_json::Value) -> Fake {
    fake(move |rec| match (rec.method.as_str(), rec.uri.as_str()) {
        ("GET", "/roles") => ok_json(roles.clone()),
        ("POST", "/roles") => (201, br#"{"name":"default","unmatched":"passthrough"}"#.to_vec()),
        ("POST", "/secrets") => (
            201,
            serde_json::json!({"secret":{"id":1,"name":"gh","created_at":0,"rotated_at":null},
                "rules":[{"id":1}],"ca_changed":true,"notice":"the CA certificate changed: agents must reload it (sg ca export)"})
            .to_string().into_bytes(),
        ),
        _ => (404, br#"{"error":"not found"}"#.to_vec()),
    })
}

#[tokio::test]
async fn secret_add_sends_the_value_and_its_first_rule_in_one_request() {
    let f = secrets_fake(serde_json::json!([{"name":"dev","unmatched":"deny"}]));
    let r = cli(&f, &["secret","add","gh","--host","api.github.com","--header","Authorization","--template","Bearer {secret}"], b"s3cr3t-value\n").await;
    r.res.unwrap();
    let log = f.log();
    let post = log.iter().find(|r| r.method == "POST" && r.uri == "/secrets").unwrap();
    let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(body["name"], "gh");
    assert_eq!(body["value"], "s3cr3t-value");
    assert_eq!(body["rules"][0]["role"], "dev", "the only role is chosen automatically");
    assert_eq!(body["rules"][0]["host_pattern"], "api.github.com");
    assert_eq!(body["rules"][0]["kind"], "header");
    assert_eq!(body["rules"][0]["template"], "Bearer {secret}");
    assert!(r.err.contains("reload"), "the CA notice goes to stderr: {}", r.err);
}

#[tokio::test]
async fn secret_add_creates_the_default_role_when_there_is_none() {
    let f = secrets_fake(serde_json::json!([]));
    cli(&f, &["secret","add","gh","--host","a.com","--header","X-Key"], b"valuevalue\n").await.res.unwrap();
    let log = f.log();
    assert!(log.iter().any(|r| r.method == "POST" && r.uri == "/roles"));
    let post = log.iter().find(|r| r.uri == "/secrets" && r.method == "POST").unwrap();
    let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(body["rules"][0]["role"], "default");
}

#[tokio::test]
async fn secret_add_with_several_roles_demands_one_and_never_leaks_the_value() {
    let f = secrets_fake(serde_json::json!([{"name":"a","unmatched":"deny"},{"name":"b","unmatched":"deny"}]));
    let r = cli(&f, &["secret","add","gh","--host","a.com","--header","X-Key"], b"valuevalue\n").await;
    let e = format!("{:#}", r.res.unwrap_err());
    assert!(e.contains("--role") && e.contains("a, b"), "{e}");
    assert!(!e.contains("valuevalue"));
    assert!(!f.log().iter().any(|r| r.method == "POST"), "nothing is created");
}
```

  (Si `cli()` expone la salida de error con otro nombre que `r.err`, usar el existente: leer cómo lo hace
  `rule_add_resolves_the_secret_and_prints_the_ca_warning_on_stderr`.) Adaptar ese test: el servidor falso devuelve
  `{"rule":{"id":4},"ca_changed":true,"notice":"..."}` y se espera el aviso en stderr desde `notice`. Eliminar
  `ca_allow_domain_prints_the_notice`.

- [x] **Paso 2: ver que falla.** `cargo test -p sg-cli` → no compila / falla.
- [x] **Paso 3: implementar.**
  - `commands.rs`: extraer los argumentos comunes y compartirlos:

```rust
#[derive(Args)]
#[command(group(clap::ArgGroup::new("target").required(true).args(["header", "query"])))]
pub struct RuleTarget {
    #[arg(long)]
    host: String,
    #[arg(long, default_value = "*")]
    path: String,
    /// Comma-separated HTTP methods (default: all)
    #[arg(long, value_delimiter = ',')]
    methods: Vec<String>,
    /// Inject into this header
    #[arg(long)]
    header: Option<String>,
    /// Inject into this query parameter (the template must be `{secret}`)
    #[arg(long)]
    query: Option<String>,
    #[arg(long, default_value = "{secret}")]
    template: String,
}

#[derive(Args)]
pub struct RuleAdd {
    #[arg(long)]
    role: String,
    #[command(flatten)]
    target: RuleTarget,
    /// Name of an existing secret
    #[arg(long)]
    secret: String,
}
```

    `SecretCmd::Add { name: String, /// Role of the first rule (default: the only role, or a new `default`) #[arg(long)] role: Option<String>, #[command(flatten)] target: RuleTarget }`. Quitar `CaCmd::AllowDomain` y su
    rama en `ca()`. Función compartida (mueve aquí la lógica de validación ya existente de `rule add`):

```rust
/// Wire form of one rule, shared by `secret add` and `rule add`.
fn rule_json(role: &str, t: &RuleTarget) -> anyhow::Result<Value> {
    let (kind, target) = match (&t.header, &t.query) {
        (Some(h), None) => ("header", h.clone()),
        (None, Some(q)) => ("query", q.clone()),
        _ => bail!("use exactly one of --header or --query"),
    };
    if kind == "query" && t.template != "{secret}" {
        bail!("--query injects the bare secret: the template must be `{{secret}}` (got `{}`)", t.template);
    }
    let methods: Vec<String> = t.methods.iter().map(|m| m.trim().to_ascii_uppercase()).filter(|m| !m.is_empty()).collect();
    Ok(json!({"role": role, "host_pattern": t.host, "path_pattern": t.path, "methods": methods,
              "kind": kind, "target_name": target, "template": t.template}))
}

/// `--role`, else the only existing role, else a new `default`.
async fn resolve_role(socket: &Path, io: &mut Io<'_>, role: Option<String>) -> anyhow::Result<String> {
    if let Some(r) = role {
        return Ok(r);
    }
    let roles = api(socket, Method::GET, "/roles", None).await?;
    let names: Vec<String> = roles.as_array().map(Vec::as_slice).unwrap_or_default().iter()
        .filter_map(|r| r["name"].as_str().map(String::from)).collect();
    match names.len() {
        0 => {
            api(socket, Method::POST, "/roles", Some(json!({"name": "default", "unmatched": "passthrough"}))).await?;
            writeln!(io.err, "note: no role existed, created role 'default' (unmatched = passthrough)")?;
            Ok("default".into())
        }
        1 => Ok(names[0].clone()),
        _ => bail!("several roles exist ({}): choose one with --role", names.join(", ")),
    }
}
```

    `rule add` usa `rule_json(&a.role, &a.target)` y conserva la resolución del `secret_id`; muestra el aviso con
    `v["notice"].as_str()`. `secret add`: lee el valor (`read_value`) **antes** de resolver el rol; construye la regla
    con `rule_json`; envía `secret_body(Some(&name), &value, Some(&json!([rule])))`; imprime
    `secret '{name}' stored with rule {id}` y, si `v["notice"]` es texto, `warning: ...` por stderr.
    `secret ls`: columnas `["ID","NAME","RULES","CREATED","ROTATED"]` con `text(s,"rules")`.
  - `input.rs`: `secret_body(name, value, rules: Option<&Value>)`: tras escribir `"value":<json>` añadir
    `,"rules":` + `serde_json::to_writer(&mut *out, rules)` si `Some`; las llamadas de `rotate` pasan `None`.
    Ajustar el test existente de `secret_body` y añadir uno con reglas (el JSON resultante parsea con `name`, `value`,
    `rules`).
  - `sg/src/main.rs`: en el texto de ayuda quitar `sg ca allow-domain github.com` (línea ~32) y, si el ejemplo
    muestra `secret add`, añadir las flags de la regla.
  - Adaptar los tests viejos: `secret_add_has_no_value_argument` y `rule_add_parses_all_flags` acceden a
    `a.host` / `a.path`… → pasan a `a.target.host` etc.
- [x] **Paso 4: adaptar `crates/sg/tests/cli_e2e.rs`** (el flujo real contra `sg serve`): sustituir
  `secret add gh` + `ca allow-domain github.com` + `rule add` por
  `secret add gh --role reviewer --host api.github.com --methods GET --header Authorization --template 'Bearer {secret}'`
  (creando antes el rol), y comprobar con `ca status` que aparece `api.github.com`.
- [x] **Paso 5: ver que pasa.** `cargo test -p sg-cli` y `cargo test -p sg --test cli_e2e`; clippy de ambos.
- [x] **Paso 6: commit.** `feat(cli): secret add takes its first rule; drop ca allow-domain`.

---

### Tarea 6: web

**Archivos:**
- Modificar: `web/app.js`, `web/style.css`
- Test: `crates/admin/tests/js/app.test.js`

**Interfaces:**
- Consume: contrato HTTP de la Tarea 4.
- Produce: formulario «Add a secret» con el bloque de la primera regla (obligatorio) y «Add another rule»; la lista de
  secretos muestra el número de reglas; la pestaña CA queda de solo lectura; `buildRule(values)` exportada para tests.

- [x] **Paso 1: tests que fallan** (`app.test.js`):

```js
test("buildRule trims, defaults the path and keeps only checked methods", () => {
  const r = app.buildRule({ role: "dev", host: " api.github.com ", path: "", methods: ["GET", "HEAD"], kind: "header", target: " Authorization ", template: "Bearer {secret}" });
  assert.deepEqual(r, {
    role: "dev", host_pattern: "api.github.com", path_pattern: "*", methods: ["GET", "HEAD"],
    kind: "header", target_name: "Authorization", template: "Bearer {secret}",
  });
});

test("secretBody never puts the value anywhere but `value` and always carries at least one rule", () => {
  const rule = { role: "dev", host_pattern: "a.com", path_pattern: "*", methods: [], kind: "header", target_name: "X", template: "{secret}" };
  const b = app.secretBody("gh", "s3cr3t", [rule]);
  assert.deepEqual(Object.keys(b), ["name", "value", "rules"]);
  assert.equal(JSON.stringify(b.rules).includes("s3cr3t"), false);
  assert.throws(() => app.secretBody("gh", "s3cr3t", []), /at least one rule/);
});
```

- [x] **Paso 2: ver que falla.** `node --test crates/admin/tests/js/app.test.js` → `buildRule is not a function`.
- [x] **Paso 3: implementar** en `app.js`:
  - Funciones puras (y exportarlas en `module.exports`):

```js
function buildRule(v) {
  return {
    role: v.role,
    host_pattern: v.host.trim(),
    path_pattern: v.path.trim() || "*",
    methods: v.methods,
    kind: v.kind,
    target_name: v.target.trim(),
    template: v.template,
  };
}

function secretBody(name, value, rules) {
  if (!rules.length) throw new Error("a secret needs at least one rule");
  return { name, value, rules };
}
```

  - Extraer de `viewRoles` los campos de regla a un componente reutilizable `ruleFields(roles, { onRemove })` que
    devuelve `{ node, read }` (`node`: `fieldset.rule-block` con rol, host, path, métodos, inyección, nombre,
    template —con la misma lógica `syncKind` para `query`—; `read()` llama a `buildRule` con los valores). Si
    `roles` está vacío, el selector de rol ofrece una única opción `["default", "default (created automatically)"]`.
    `onRemove` (si se pasa) añade un botón «Remove this rule».
  - `viewRoles`: el formulario «Add a rule» pasa a usar `ruleFields(roles)` más el selector de secreto
    (`secret_id: Number(secret.value)`); sustituir `res.ca_warning` por `res.notice`.
  - `viewSecrets`: cargar `roles` (`GET /roles`); la tabla incluye la columna «Rules»
    (`s.rules` o `el("span", {class:"bad"}, "none: never injected")` si es 0). El formulario tiene nombre, valor y
    una lista de bloques de regla: el primero sin botón de quitar; «Add another rule» añade bloques con
    «Remove this rule». Al enviar:

```js
onsubmit: safe(async () => {
  const rules = blocks.map((b) => b.read());
  const body = secretBody(name.value, value.value, rules);
  value.value = ""; // clear immediately: the value must not linger in the page
  if (!roles.length) {
    try {
      await api("POST", "/roles", { name: "default", unmatched: "passthrough" });
    } catch (e) {
      if (!/already exists/.test(e.message)) throw e;
    }
  }
  const res = await api("POST", "/secrets", body);
  await refresh();
  if (res && res.notice) notify(`Secret "${body.name}" added. ${res.notice}`, "notice");
  else notify(`Secret "${body.name}" added.`);
}),
```

    (`blocks` es el array de `ruleFields(...)` vigente; al quitar uno se elimina del array y del DOM.)
  - `viewCa`: eliminar el formulario «Allow domain» y el `POST /ca/domains`; cambiar el texto de ayuda a «Domains are
    derived from your rules: adding a rule for a new host permits it here. When the list changes, agents must reload
    the CA certificate.» y el estado vacío a «No domains yet: they appear when you add a rule.».
  - `style.css`: `.rule-block { margin: .5rem 0; width: 100%; }` y que `fieldset.rule-block` herede el estilo de tarjeta
    existente (bordes de `fieldset`).
- [x] **Paso 4: ver que pasa.** `node --test crates/admin/tests/js/app.test.js` y
  `cargo test -p sg-admin --test web_assets` (el test de CSP/activos embebidos y de Node).
- [x] **Paso 5: comprobar en un navegador real** (lo único que la fase 1 no tuvo): compilar
  (`cargo build --release`), arrancar una instancia desechable (`sg keygen --out /tmp/sg-ui.key`, `sg serve --data-dir
  /tmp/sg-ui --key-file /tmp/sg-ui.key --proxy-bind 127.0.0.1:18080 --admin-bind 127.0.0.1:19090 --socket
  /tmp/sg-ui/sg.sock`), abrir el enlace de `sg login-url` con Chromium headless + CDP y capturar: alta de secreto
  con 1 y con 2 reglas, error por regla inválida, pestaña CA. Revisar las capturas (no hay captura automática en CI).
- [x] **Paso 6: commit.** `feat(web): add secrets together with their rules; CA view is read-only`.

---

### Tarea 7: scripts, documentación y verificación final

**Archivos:**
- Modificar: `scripts/e2e.sh`, `scripts/e2e-docker.sh`, `README.md`, `docs/{README,architecture,database-schema,policy-and-rules,tokens-and-ca,cli-reference,admin-api,security-model,operations,testing}.md`
- Marcar este plan como ejecutado.

- [x] **Paso 1: scripts.** `e2e.sh`: la primera regla de `api-key` pasa a nacer con el secreto y desaparece
  `ca allow-domain localhost`:

```bash
sg role add developer --unmatched deny >/dev/null
sg role add reviewer --unmatched deny >/dev/null
sg role add restricted --unmatched deny >/dev/null
sg role add querier --unmatched deny >/dev/null
sg role add keyer --unmatched deny >/dev/null
printf '%s' "$SECRET" | sg secret add api-key --role developer --host localhost --header Authorization --template 'Bearer {secret}' >/dev/null || die "secret add"
sg rule add --role reviewer   --host localhost --methods GET --header Authorization --template 'Bearer {secret}' --secret api-key >/dev/null
# (restricted, querier, keyer: igual que ahora)
```

  `e2e-docker.sh`: igual (`docker exec -i "$NAME" sg --socket /data/sg.sock secret add api-key --role developer --host "$UPHOST" --header Authorization --template 'Bearer {secret}'`),
  quitando `ca allow-domain`; los roles se crean antes. Añadir en ambos una comprobación de que `sg ca status` lista el
  host y de que `secret add` sin reglas falla.
- [x] **Paso 2: documentación (en inglés, como el resto de `docs/`).**
  - `README.md`: quickstart con `secret add ... --host ... --header ...` (sin `allow-domain`), explicación de «un
    secreto = valor + primera regla», y el aviso de recargar el PEM al añadir hosts.
  - `cli-reference.md`: nueva sintaxis de `secret add`, `ca` sin `allow-domain`, columna `RULES`, resolución de rol.
  - `admin-api.md`: contratos de la Tarea 4 (cuerpos, respuestas, 400/409, `/ca/domains` eliminado, ejemplo de
    `curl` por el socket).
  - `tokens-and-ca.md`: la CA se deriva de las reglas, `*.x → x`, reemisión al añadir/quitar, placeholder, sincronización
    al arrancar, qué debe hacer el agente (recargar el PEM al **añadir**).
  - `policy-and-rules.md` y `database-schema.md`: invariante «≥1 regla por secreto», cascada, 409 de rol/regla.
  - `security-model.md`: la CA ya no se amplía a mano; consecuencias de `*.x → x` y de que crear una regla amplía la
    confianza de la CA.
  - `operations.md`: migración (los dominios manuales sin regla se retiran en el primer arranque; secretos sin reglas
    previos siguen válidos y se marcan en la web).
  - `architecture.md`: módulo `ops`, orden de locks conexión → estado → caché.
  - `testing.md`/`README.md`/`docs/README.md`: recuento de tests tras la verificación final.
- [x] **Paso 3: verificación (el workspace completo, una sola vez).**

```bash
source ~/.cargo/env
cd ~/Repositorios/personal_projects/secret_guardian
cargo test --workspace 2>&1 | tail -40
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo build --release
scripts/e2e.sh
scripts/e2e-docker.sh
```

  Esperado: 0 fallos en el workspace, clippy y fmt limpios, `E2E OK` y `E2E DOCKER OK`. Mostrar la salida. Si algo
  falla, parar y arreglar antes de revisar.
- [x] **Paso 4: actualizar los recuentos en `docs/testing.md`, `docs/README.md` y `README.md`** con el número real.
- [x] **Paso 5: commit.** `docs: document required rules per secret and the derived CA` (y, si el recuento cambia en
  otro commit, `docs: refresh test inventory`).
- [x] **Paso 6: recordatorio.** Pasada de revisión final (`/ship`): diff completo, revisión de seguridad de lo
  tocado (autenticación/CA/entrada externa), deriva respecto a la spec; integración la decide el operador.

---

## Autorrevisión

- **Cobertura de la spec §7.5:** invariante y alta atómica (T1, T4), 400/409 (T4), cascada (T1, T4), secretos previos
  sin reglas (T4: siguen existiendo; T6: aviso), rol por defecto (T5 y T6), CA derivada y sincronización al arrancar
  (T2–T4), `ca_changed` y aviso (T4–T6), eliminación de `allow-domain` (T4–T7), borrado de rol (T1 spec, T4), pruebas
  de API/CA/CLI/web (T1–T6). §7.3/7.4: T5/T6. §10 fase 2b y `security-model` ya están escritas.
- **Marcadores de relleno:** ninguno; los pasos que dicen «adaptar» listan los tests concretos y qué cambia.
- **Consistencia de tipos:** `RuleSpec`/`NewRule` (T2) → `ops::create_secret` (T4); `PreparedCa`, `prepare_domains`,
  `persist`, `install` (T3) → `plan_ca` (T4); `in_transaction`, `add_secret_with`, `remove_secret_cascade_with` (T1) →
  T3 tests y T4; respuesta `{secret, rules, ca_changed, notice}` (T4) → CLI (T5) y web (T6).
- **Riesgo conocido:** `plan_ca` firma y sondea certificados mientras la conexión SQLite está bloqueada, así que el
  proxy espera unos milisegundos en cada alta o borrado que cambia dominios; aceptable para un operador, y se
  documenta en `docs/architecture.md`.
