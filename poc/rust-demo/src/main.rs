//! Agent-session demo: every tool call is authorized by Dogwood first, and the
//! stubbed tool only runs on Allow. All policy logic lives in ../policies and
//! ../schema; this file only wires the pipeline and plays a scripted session.

use dogwood_language::{
    Authorizer, Decision, Event, LoweredPolicySet, PolicySchema, ServiceSchema, Validator, Value,
};

const SCHEMA: &str = include_str!("../../schema/gateway.cedarschema");
const POLICIES: &str = include_str!("../../policies/gateway.dw");

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// One tool call the agent wants to make on behalf of an OAuth user.
struct Call {
    t: i64,
    user: &'static str,
    action: &'static str,
    path: &'static str,
    sensitivity: Option<&'static str>,
}

const fn call(t: i64, user: &'static str, action: &'static str, path: &'static str) -> Call {
    Call { t, user, action, path, sensitivity: None }
}
const fn sens(mut c: Call, s: &'static str) -> Call {
    c.sensitivity = Some(s);
    c
}

/// Build an event of `kind` ("request" or "response") for a call. Input fields
/// are supplied twice: `.field` feeds the temporal history, `.request_context`
/// feeds `context.input.*` in plain `when { .. }` conditions (see README).
fn event(kind: &str, c: &Call) -> Event {
    let mut b = Event::builder(&format!("Drupe::Action::{}", c.action), kind)
        .timestamp(c.t)
        .principal(&format!("Drupe::OAuthUser::\"{}\"", c.user))
        .resource("Drupe::Gateway::\"gw1\"");
    let mut inputs = vec![("user", c.user)];
    if c.action != "Login" {
        inputs.push(("path", c.path));
    }
    if let Some(s) = c.sensitivity {
        inputs.push(("sensitivity", s));
    }
    for (k, v) in inputs {
        b = b.field("input", k, Value::String(v.to_string()));
        b = b.request_context("input", k, Value::String(v.to_string()));
    }
    b.build()
}

/// Load schema + policies from the files, validate, and return a fresh
/// (empty-history) authorizer. No policy logic is hard-coded here.
fn new_authorizer() -> Res<Authorizer> {
    let service = ServiceSchema::defaults();
    let schema = PolicySchema::from_cedarschema_str(SCHEMA)?;
    let policies = LoweredPolicySet::from_str(POLICIES, &service, &schema)?;
    let report = Validator::new().validate(&policies);
    assert!(report.validation_passed(), "policy validation failed");
    Ok(Authorizer::new(policies))
}

/// The stubbed tool backend: only reached if the gateway authorized the call.
fn run_tool(c: &Call) -> String {
    format!("tool {}({}) executed", c.action, c.path)
}

/// Authorize a call, then run the tool on Allow. Returns the decision, the
/// determining rule indices and what the tool did.
fn gateway(az: &mut Authorizer, c: &Call) -> (Decision, Vec<usize>, String) {
    let resp = az
        .is_authorized(&event("request", c))
        .expect("`request` is a decision kind, so a Response is expected");
    let rules: Vec<usize> = resp.diagnostics().reason().map(|r| r.rule_index).collect();
    let outcome = if resp.decision() == Decision::Allow {
        let out = run_tool(c);
        // Report the result back to the authorizer as a history-only event.
        // This is what the `Login::response` temporal leaf looks for.
        let hist = az.is_authorized(&event("response", c));
        assert!(hist.is_none(), "`response` is history-only: expect None");
        out
    } else {
        "BLOCKED (tool not run)".to_string()
    };
    (resp.decision(), rules, outcome)
}

fn show(az: &mut Authorizer, c: &Call) {
    let (d, rules, outcome) = gateway(az, c);
    println!(
        "@{:<5} {:<6} {:<22} {:<5} rules={:<5} {}",
        c.t,
        c.action,
        c.sensitivity.map_or(c.path.to_string(), |s| format!("{} [{}]", c.path, s)),
        format!("{:?}", d).to_uppercase(),
        format!("{:?}", rules),
        outcome
    );
}

fn main() -> Res<()> {
    // ---- 1. A scripted agent session through one stateful Authorizer. ----
    println!("== Session 1: alice's agent (one Authorizer, history accumulates) ==");
    let mut az = new_authorizer()?;
    let session = [
        call(0, "alice", "Write", "/docs/a"), // no login yet -> Deny
        call(10, "alice", "Login", "-"),
        call(20, "alice", "Read", "/docs/a"),
        call(60, "alice", "Write", "/docs/a"), // login 50s ago -> Allow
        sens(call(90, "alice", "Delete", "/vault/x"), "high"), // forbid wins
        sens(call(100, "alice", "Export", "/tmp/x"), "low"),
        sens(call(160, "alice", "Export", "/tmp/x"), "low"),
        sens(call(220, "alice", "Export", "/tmp/x"), "low"), // 3rd in 10m -> Deny
        call(7200, "alice", "Write", "/docs/a"), // login expired -> Deny
    ];
    for c in &session {
        show(&mut az, c);
    }

    // ---- 2. Same Write, but on an authorizer that never saw the Login. ----
    println!("\n== Session 2: statefulness check (fresh Authorizer, no Login in history) ==");
    let mut fresh = new_authorizer()?;
    show(&mut fresh, &call(60, "alice", "Write", "/docs/a"));
    println!("(identical to session 1's @60 Write, which was ALLOWed: the verdict came from history)");

    // ---- 3. Option<Response>: Some for requests, None for history-only. ----
    println!("\n== Option<Response> ==");
    let mut az = new_authorizer()?;
    let login = call(0, "alice", "Login", "-");
    let req = az.is_authorized(&event("request", &login));
    println!("Login request  -> {}", if req.is_some() { "Some(Response)" } else { "None" });
    let resp = az.is_authorized(&event("response", &login));
    println!("Login response -> {}", if resp.is_some() { "Some(Response)" } else { "None" });
    assert!(req.is_some() && resp.is_none());
    Ok(())
}
