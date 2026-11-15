//! `github` tools driven through the dispatcher against a loopback API.

use serde_json::{json, Value};

use crate::testkit::{text_of, HttpMock, Kit, Reply, Seen};

/// Cargo sets this for test binaries, which makes it a variable with a known
/// value that no test has to write.
const TOKEN_ENV: &str = "CARGO_PKG_NAME";
const TOKEN: &str = env!("CARGO_PKG_NAME");

fn kit(api: &HttpMock, token_env: &str, security: &str) -> Kit {
    Kit::with_config(
        &format!("allow_network = true\nallow_private_network = true\n{security}"),
        &format!(
            "[github]\napi_url = \"{}\"\ntoken_env = \"{token_env}\"",
            api.url()
        ),
    )
}

fn reply(status: u16, body: &Value) -> Reply {
    (status, Vec::new(), body.to_string())
}

fn path_of(seen: &Seen) -> &str {
    seen.target.split('?').next().unwrap_or_default()
}

#[tokio::test]
async fn lists_are_reduced_to_their_fields_and_carry_the_token() {
    let api = HttpMock::start(|seen| match path_of(seen) {
        "/repos/o/r/pulls" => reply(
            200,
            &json!([{
                "number": 7, "title": "Add it", "state": "open", "draft": false,
                "user": {"login": "ann"}, "head": {"ref": "feat"}, "base": {"ref": "main"},
                "html_url": "https://github.com/o/r/pull/7",
                "updated_at": "2026-01-01T00:00:00Z", "body": "not returned",
            }]),
        ),
        "/repos/o/r/issues" => reply(
            200,
            &json!([
                {"number": 1, "title": "Bug", "state": "open", "user": null,
                 "labels": [{"name": "bug"}, {"name": "p1"}], "comments": 2,
                 "html_url": "https://github.com/o/r/issues/1", "updated_at": null},
                {"number": 7, "title": "Add it", "state": "open", "pull_request": {}},
            ]),
        ),
        "/repos/o/r/actions/runs" => reply(
            200,
            &json!({"total_count": 1, "workflow_runs": [{
                "id": 99, "name": "CI", "status": "completed", "conclusion": "failure",
                "head_branch": "main", "event": "push", "head_sha": "abc",
                "html_url": "https://github.com/o/r/actions/runs/99", "created_at": null,
            }]}),
        ),
        _ => reply(404, &json!({"message": "Not Found"})),
    });
    let kit = kit(&api, TOKEN_ENV, "");

    let pulls = kit
        .json("github_pr_list", json!({"owner": "o", "repo": "r"}))
        .await;
    assert_eq!(
        pulls,
        json!({"pullRequests": [{
            "number": 7, "title": "Add it", "state": "open", "draft": false, "author": "ann",
            "head": "feat", "base": "main", "url": "https://github.com/o/r/pull/7",
            "updatedAt": "2026-01-01T00:00:00Z",
        }]})
    );
    let issues = kit
        .json(
            "github_issue_list",
            json!({"owner": "o", "repo": "r", "state": "all", "labels": ["bug", "p 1"], "perPage": 5}),
        )
        .await;
    assert_eq!(issues["issues"].as_array().unwrap().len(), 1, "{issues}");
    assert_eq!(issues["issues"][0]["labels"], json!(["bug", "p1"]));
    assert_eq!(issues["issues"][0]["author"], Value::Null);
    let runs = kit
        .json(
            "github_workflow_runs",
            json!({"owner": "o", "repo": "r", "branch": "main"}),
        )
        .await;
    assert_eq!(runs["runs"][0]["conclusion"], "failure");

    let seen = api.seen();
    assert_eq!(seen[0].method, "GET");
    assert_eq!(
        seen[0].target,
        "/repos/o/r/pulls?state=open&per_page=30&page=1"
    );
    assert_eq!(
        seen[1].target,
        "/repos/o/r/issues?state=all&labels=bug%2Cp%201&per_page=5&page=1"
    );
    for request in &seen {
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert_eq!(
            request.header("accept"),
            Some("application/vnd.github+json")
        );
        assert!(request
            .header("user-agent")
            .unwrap()
            .starts_with("nebula-mcp/"));
    }
}

#[tokio::test]
async fn the_token_goes_to_the_api_host_and_nowhere_else() {
    let elsewhere = HttpMock::start(|_| reply(200, &json!({"elsewhere": true})));
    let target = format!("{}/landing", elsewhere.url());
    let api = HttpMock::start(move |seen| match path_of(seen) {
        "/moved" => (
            302,
            vec![("Location".to_string(), target.clone())],
            String::new(),
        ),
        _ => reply(200, &json!({"ok": true})),
    });
    let kit = kit(&api, TOKEN_ENV, "");

    // A path cannot name another host, whatever its shape.
    for path in [
        "https://evil.example/x",
        "//evil.example/x",
        "@evil.example/x",
        "evil.example/x",
        "/../x",
        "/a/./b",
        "/x?access_token=1",
        "/a b",
        "\\\\evil.example\\x",
        "/x#frag",
    ] {
        let err = kit.err("github_request", json!({"path": path})).await;
        assert!(err.starts_with("[invalid_arguments]"), "{path}: {err}");
    }
    for (owner, repo) in [("o/../..", "r"), ("o", "r/pulls?x"), ("", "r"), ("..", "r")] {
        let err = kit
            .err("github_pr_list", json!({"owner": owner, "repo": repo}))
            .await;
        assert!(
            err.starts_with("[invalid_arguments]"),
            "{owner}/{repo}: {err}"
        );
    }
    assert!(api.seen().is_empty() && elsewhere.seen().is_empty());

    // The API redirects to another origin: the request follows, the token
    // does not.
    let out = kit.ok("github_request", json!({"path": "/moved"})).await;
    assert!(
        text_of(&out).contains("\"elsewhere\": true"),
        "{}",
        text_of(&out)
    );
    assert!(api.seen()[0].header("authorization").is_some());
    let landed = elsewhere.seen();
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].target, "/landing");
    assert_eq!(landed[0].header("authorization"), None);
}

#[tokio::test]
async fn writes_need_a_token_and_delete_needs_the_gate() {
    let api = HttpMock::start(|seen| match (seen.method.as_str(), path_of(seen)) {
        ("POST", "/repos/o/r/pulls") => reply(
            201,
            &json!({"number": 12, "html_url": "https://github.com/o/r/pull/12"}),
        ),
        ("POST", "/repos/o/r/pulls/12/reviews") => reply(
            200,
            &json!({"id": 5, "state": "APPROVED", "html_url": "https://github.com/o/r/pull/12#r5"}),
        ),
        ("DELETE", _) => (204, Vec::new(), String::new()),
        _ => reply(200, &json!([])),
    });

    // Without a token: reads go out anonymously, writes are refused here.
    let anonymous = kit(&api, "NEBULA_TEST_NO_SUCH_VARIABLE", "");
    anonymous
        .json("github_labels_list", json!({"owner": "o", "repo": "r"}))
        .await;
    assert_eq!(api.seen()[0].header("authorization"), None);
    let err = anonymous
        .err(
            "github_pr_create",
            json!({"owner": "o", "repo": "r", "title": "t", "head": "h", "base": "main"}),
        )
        .await;
    assert!(
        err.starts_with("[permission_denied]") && err.contains("NEBULA_TEST_NO_SUCH_VARIABLE"),
        "{err}"
    );
    assert_eq!(api.seen().len(), 1);

    let kit = kit(&api, TOKEN_ENV, "");
    let created = kit
        .json(
            "github_pr_create",
            json!({"owner": "o", "repo": "r", "title": "Add it", "head": "feat", "base": "main",
                   "body": "Why.", "draft": true}),
        )
        .await;
    assert_eq!(
        created,
        json!({"number": 12, "url": "https://github.com/o/r/pull/12"})
    );
    let sent: Value = serde_json::from_str(&api.seen()[1].body).unwrap();
    assert_eq!(
        sent,
        json!({"title": "Add it", "head": "feat", "base": "main", "body": "Why.", "draft": true})
    );
    assert_eq!(
        api.seen()[1].header("content-type"),
        Some("application/json")
    );
    let review = kit
        .json(
            "github_review_create",
            json!({"owner": "o", "repo": "r", "pull": 12, "event": "APPROVE"}),
        )
        .await;
    assert_eq!(review["state"], "APPROVED");
    let err = kit
        .err(
            "github_review_create",
            json!({"owner": "o", "repo": "r", "pull": 12, "event": "REQUEST_CHANGES"}),
        )
        .await;
    assert!(err.starts_with("[invalid_arguments]"), "{err}");

    let delete = json!({"method": "DELETE", "path": "/repos/o/r/git/refs/heads/old"});
    let err = kit.err("github_request", delete.clone()).await;
    assert!(
        err.starts_with("[permission_denied]") && err.contains("allow_destructive"),
        "{err}"
    );
    assert!(api.seen().iter().all(|s| s.method != "DELETE"));

    // With the network off nothing is sent at all.
    let before = api.seen().len();
    kit.reconfigure("");
    let err = kit
        .err("github_pr_list", json!({"owner": "o", "repo": "r"}))
        .await;
    assert!(
        err.starts_with("[permission_denied]") && err.contains("allow_network"),
        "{err}"
    );
    assert_eq!(api.seen().len(), before);
}

#[tokio::test]
async fn a_gated_delete_goes_through_and_errors_say_what_to_change() {
    let api = HttpMock::start(|seen| match (seen.method.as_str(), path_of(seen)) {
        ("DELETE", _) => (204, Vec::new(), String::new()),
        (_, "/repos/o/missing/releases") => reply(404, &json!({"message": "Not Found"})),
        (_, "/repos/o/locked/releases") => reply(401, &json!({"message": "Bad credentials"})),
        (_, "/repos/o/broken/releases") => reply(500, &json!({"message": "Server Error"})),
        ("POST", "/repos/o/r/releases") => reply(
            422,
            &json!({"message": "Validation Failed", "errors": [{"code": "already_exists"}]}),
        ),
        _ => reply(200, &json!([])),
    });
    let kit = kit(&api, TOKEN_ENV, "allow_destructive = true");
    let out = kit
        .ok(
            "github_request",
            json!({"method": "DELETE", "path": "/repos/o/r/git/refs/heads/old",
                   "query": {"note": "a b"}}),
        )
        .await;
    assert_eq!(text_of(&out), "[github_request: 204 DELETE]");
    assert_eq!(
        api.seen()[0].target,
        "/repos/o/r/git/refs/heads/old?note=a%20b"
    );

    for (repo, prefix) in [
        ("missing", "[not_found]"),
        ("locked", "[permission_denied]"),
        ("broken", "[execution]"),
    ] {
        let err = kit
            .err("github_release_list", json!({"owner": "o", "repo": repo}))
            .await;
        assert!(err.starts_with(prefix), "{repo}: {err}");
    }
    let err = kit
        .err(
            "github_release_create",
            json!({"owner": "o", "repo": "r", "tag": "v1"}),
        )
        .await;
    assert!(
        err.starts_with("[invalid_arguments]") && err.contains("already_exists"),
        "{err}"
    );
    assert!(!err.contains(TOKEN), "the token leaked into an error");
}
