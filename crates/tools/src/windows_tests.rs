//! `windows` tools: argument checks everywhere, the tools themselves on
//! Windows.

#![allow(clippy::disallowed_methods)]

use super::{plain, registry_key, registry_type, task_name, variable_name};

#[test]
fn registry_keys_are_normalised_and_confined_to_hives() {
    assert_eq!(
        registry_key("hkcu\\Software\\App").unwrap(),
        ("HKEY_CURRENT_USER\\Software\\App".to_string(), true)
    );
    assert_eq!(
        registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE").unwrap(),
        ("HKEY_LOCAL_MACHINE\\SOFTWARE".to_string(), false)
    );
    assert_eq!(registry_key("HKU").unwrap().0, "HKEY_USERS");
    for bad in [
        "",
        "Software\\App",
        "\\\\server\\HKLM\\Software",
        "C:\\Windows",
        "HKCU\\..\\..\\x",
        "HKCU/Software",
        "HKCU\\Soft*",
        "HKCU\\a`b",
        "Env:\\PATH",
    ] {
        assert!(registry_key(bad).is_err(), "{bad}");
    }
    assert_eq!(registry_type("REG_DWORD"), "DWord");
    assert_eq!(registry_type("REG_SZ"), "String");
}

#[test]
fn names_cannot_be_wildcards_or_options() {
    for bad in ["*", "Win*", "a?c", "[abc]", "", "a\nb", "a`b"] {
        assert!(plain(bad, "name", 256).is_err(), "{bad:?}");
    }
    assert!(plain("Windows Update (wuauserv)", "name", 256).is_ok());

    for bad in ["/delete", "/tn x /f", "-x", "a\"b", "*"] {
        assert!(task_name(bad).is_err(), "{bad}");
    }
    assert!(task_name("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag").is_ok());

    for bad in ["", "1A", "A B", "A=B", "A;B", "$x"] {
        assert!(variable_name(bad).is_err(), "{bad}");
    }
    assert!(variable_name("ProgramFiles(x86)").is_ok());
}

#[cfg(windows)]
mod live {
    use serde_json::{json, Value};

    use crate::testkit::{text_of, Kit};

    fn parsed(kit_output: &nebula_mcp_core::ToolOutput) -> Value {
        let text = text_of(kit_output);
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
    }

    #[tokio::test]
    async fn services_are_listed_and_guarded() {
        let kit = Kit::new("");
        let one = parsed(&kit.ok("windows_service", json!({"name": "EventLog"})).await);
        assert_eq!(one["Name"], "EventLog");
        assert_eq!(one["Status"], "Running");
        let all = parsed(&kit.ok("windows_service", json!({})).await);
        assert!(all.as_array().unwrap().len() > 10);

        for action in ["start", "stop", "restart"] {
            let err = kit
                .err(
                    "windows_service",
                    json!({"name": "EventLog", "action": action}),
                )
                .await;
            assert!(
                err.starts_with("[permission_denied]") && err.contains("allow_elevated"),
                "{action}: {err}"
            );
        }
        // Elevated alone is not enough to stop something.
        kit.reconfigure("allow_elevated = true");
        let err = kit
            .err(
                "windows_service",
                json!({"name": "EventLog", "action": "stop"}),
            )
            .await;
        assert!(err.contains("allow_destructive"), "{err}");
        let err = kit
            .err("windows_service", json!({"name": "*", "action": "query"}))
            .await;
        assert!(err.starts_with("[invalid_arguments]"), "{err}");
        let err = kit
            .err("windows_service", json!({"name": "NoSuchServiceHere"}))
            .await;
        assert!(err.starts_with("[execution]"), "{err}");
    }

    #[tokio::test]
    async fn the_registry_round_trips_values_as_data() {
        let kit = Kit::new("");
        let key = format!("HKCU\\Software\\NebulaMcpTest-{}", std::process::id());
        // Text that would be code if it were ever pasted into a script.
        let tricky = "'; Remove-Item C:\\ -Recurse; $(whoami) `n \"q\"";
        kit.ok(
            "windows_registry",
            json!({"action": "set", "key": key, "value": "text", "data": tricky}),
        )
        .await;
        kit.ok(
            "windows_registry",
            json!({"action": "set", "key": key, "value": "number", "type": "REG_DWORD",
                   "data": "4294967295"}),
        )
        .await;
        kit.ok(
            "windows_registry",
            json!({"action": "set", "key": key, "value": "lines", "type": "REG_MULTI_SZ",
                   "data": "one\ntwo"}),
        )
        .await;
        let got = parsed(
            &kit.ok(
                "windows_registry",
                json!({"action": "query", "key": key, "value": "text"}),
            )
            .await,
        );
        assert_eq!(got["data"], tricky);
        assert_eq!(got["type"], "String");
        let whole = parsed(
            &kit.ok("windows_registry", json!({"action": "query", "key": key}))
                .await,
        );
        assert_eq!(whole["values"]["number"], 4_294_967_295u64);
        assert_eq!(whole["values"]["lines"], json!(["one", "two"]));

        let delete = json!({"action": "delete", "key": key});
        let err = kit.err("windows_registry", delete.clone()).await;
        assert!(err.contains("allow_destructive"), "{err}");
        let err = kit
            .err(
                "windows_registry",
                json!({"action": "set", "key": "HKLM\\Software\\NebulaMcpTest", "value": "v",
                       "data": "x"}),
            )
            .await;
        assert!(err.contains("allow_elevated"), "{err}");

        kit.reconfigure("allow_destructive = true");
        let err = kit
            .err(
                "windows_registry",
                json!({"action": "delete", "key": "HKCU\\Software"}),
            )
            .await;
        assert!(err.starts_with("[invalid_arguments]"), "{err}");
        kit.ok("windows_registry", delete).await;
        let err = kit
            .err("windows_registry", json!({"action": "query", "key": key}))
            .await;
        assert!(err.starts_with("[execution]"), "{err}");
    }

    #[tokio::test]
    async fn persistent_environment_variables_round_trip() {
        let kit = Kit::new("allow_destructive = true");
        let name = format!("NEBULA_TEST_{}", std::process::id());
        let value = "a b;c & %PATH% $(x)";
        kit.ok(
            "windows_env",
            json!({"action": "set", "name": name, "value": value}),
        )
        .await;
        let got = parsed(
            &kit.ok("windows_env", json!({"action": "get", "name": name}))
                .await,
        );
        assert_eq!(got["value"], value);
        kit.ok("windows_env", json!({"action": "delete", "name": name}))
            .await;
        let got = parsed(
            &kit.ok("windows_env", json!({"action": "get", "name": name}))
                .await,
        );
        assert_eq!(got["value"], Value::Null);
        let err = kit
            .err(
                "windows_env",
                json!({"action": "set", "name": name, "value": "x", "scope": "Machine"}),
            )
            .await;
        assert!(err.contains("allow_elevated"), "{err}");
    }

    #[tokio::test]
    async fn read_only_inventories_answer_with_json() {
        let kit = Kit::new("");
        let events = parsed(
            &kit.ok(
                "windows_event_log",
                json!({"logName": "System", "maxEvents": 3}),
            )
            .await,
        );
        assert!(events.is_array() || events.is_object(), "{events}");
        let err = kit
            .err("windows_event_log", json!({"logName": "No Such Log"}))
            .await;
        assert!(err.starts_with("[execution]"), "{err}");

        let counters = parsed(
            &kit.ok(
                "windows_perf_counters",
                json!({"counters": ["\\Memory\\Available MBytes"]}),
            )
            .await,
        );
        assert!(counters.to_string().contains("value"), "{counters}");
        let err = kit
            .err("windows_perf_counters", json!({"counters": ["Memory"]}))
            .await;
        assert!(err.starts_with("[invalid_arguments]"), "{err}");

        parsed(&kit.ok("windows_firewall", json!({"limit": 2})).await);
        parsed(&kit.ok("windows_network_adapters", json!({})).await);

        let tasks = text_of(&kit.ok("windows_scheduled_tasks", json!({})).await);
        assert!(tasks.contains('\\'), "{tasks}");
        let err = kit
            .err(
                "windows_scheduled_tasks",
                json!({"action": "run", "taskName": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"}),
            )
            .await;
        assert!(err.contains("allow_elevated"), "{err}");
        let err = kit
            .err(
                "windows_scheduled_tasks",
                json!({"action": "query", "taskName": "/delete"}),
            )
            .await;
        assert!(err.starts_with("[invalid_arguments]"), "{err}");
    }
}
