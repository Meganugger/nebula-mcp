//! `browser` tools: refusals everywhere; a real page where a browser is
//! installed (`NEBULA_TEST_BROWSER=1`, which CI sets).

#![allow(clippy::disallowed_methods)]

use serde_json::json;

use crate::testkit::{HttpMock, Kit, Reply};

const LOCAL: &str = "allow_network = true\nallow_private_network = true";

fn html(body: &str) -> Reply {
    (
        200,
        vec![("Content-Type".to_string(), "text/html".to_string())],
        body.to_string(),
    )
}

#[tokio::test]
async fn refusals_come_before_any_browser_starts() {
    let kit = Kit::new("");
    let shot = |url: &str, path: &str| json!({"url": url, "outputPath": path});
    let err = kit
        .err("browser_screenshot", shot("https://example.com/", "a.png"))
        .await;
    assert!(
        err.starts_with("[permission_denied]") && err.contains("allow_network"),
        "{err}"
    );

    kit.reconfigure("allow_network = true");
    let outside = kit.outside.join("a.png").display().to_string();
    for (url, path, prefix) in [
        ("file:///etc/passwd", "a.png", "[invalid_arguments]"),
        ("chrome://settings", "a.png", "[invalid_arguments]"),
        ("javascript:alert(1)", "a.png", "[invalid_arguments]"),
        ("http://127.0.0.1:1/", "a.png", "[network_not_allowed]"),
        ("http://169.254.169.254/", "a.png", "[network_not_allowed]"),
        ("https://example.com/", outside.as_str(), "[path_not_allowed]"),
        ("https://example.com/", ".env", "[permission_denied]"),
    ] {
        let err = kit.err("browser_screenshot", shot(url, path)).await;
        assert!(err.starts_with(prefix), "{url} -> {path}: {err}");
    }
    let err = kit
        .err(
            "browser_capture",
            json!({"url": "https://example.com/", "pdfPath": ".git/hooks/pre-commit"}),
        )
        .await;
    assert!(err.starts_with("[permission_denied]"), "{err}");
    assert!(!kit.exists("a.png") && !kit.outside.join("a.png").exists());
}

/// A module the client planted next to its files must never run, whether or
/// not a real Playwright is installed.
#[tokio::test]
async fn playwright_is_not_loaded_from_a_directory_the_client_can_write() {
    let page = HttpMock::start(|_| html("<title>t</title>hello"));
    let kit = Kit::new(LOCAL);
    let marker = kit.root.join("planted-module-ran");
    let planted = format!(
        "require('fs').writeFileSync({}, 'x'); module.exports = {{}};",
        serde_json::to_string(&marker.display().to_string()).unwrap()
    );
    for name in ["playwright", "playwright-core"] {
        kit.write(&format!("node_modules/{name}/index.js"), &planted);
        kit.write(
            &format!("node_modules/{name}/package.json"),
            &format!("{{\"name\": \"{name}\", \"main\": \"index.js\"}}"),
        );
    }
    let answered = kit
        .call("browser_capture", json!({"url": page.url(), "timeoutSecs": 30}))
        .await;
    if let Err(failure) = &answered {
        assert!(!failure.text.starts_with("[internal]"), "{}", failure.text);
    }
    assert!(!marker.exists(), "the planted module was loaded");
    // No partial output is left behind either way.
    let leftovers = std::fs::read_dir(&kit.root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
        .count();
    assert_eq!(leftovers, 0);
}

#[tokio::test]
async fn a_page_is_captured_and_its_requests_obey_the_network_policy() {
    if std::env::var_os("NEBULA_TEST_BROWSER").is_none() {
        return;
    }
    let secret = HttpMock::start(|_| html("internal secret"));
    let secret_port = secret.port;
    let page = HttpMock::start(move |seen| match seen.target.as_str() {
        "/" => html(&format!(
            "<html><head><title>Nebula test page</title></head><body><h1>Rendered</h1>\
             <p id=\"out\">before</p><script>\
             console.log('from the page');\
             document.getElementById('out').textContent = 'after script';\
             fetch('http://localhost:{secret_port}/secret').catch(() => {{}});\
             </script></body></html>"
        )),
        _ => (404, Vec::new(), String::new()),
    });
    // 127.0.0.1 is allowed by name; `localhost` is not, though it is the
    // same machine.
    let kit = Kit::new(&format!("{LOCAL}\nallowed_hosts = [\"127.0.0.1\"]"));

    let got = kit
        .json(
            "browser_capture",
            json!({"url": page.url(), "collectConsole": true, "collectNetwork": true,
                   "waitMs": 500, "screenshotPath": "shots/page.png", "timeoutSecs": 60}),
        )
        .await;
    assert_eq!(got["title"], "Nebula test page", "{got}");
    assert_eq!(got["status"], 200);
    let text = got["text"].as_str().unwrap();
    assert!(text.contains("Rendered") && text.contains("after script"), "{text}");
    assert!(got["console"].to_string().contains("from the page"), "{got}");
    assert!(got["blockedRequests"].as_u64().unwrap() >= 1, "{got}");
    assert!(secret.seen().is_empty(), "the page reached a host policy refuses");
    let png = std::fs::read(kit.root.join("shots/page.png")).unwrap();
    assert!(png.starts_with(b"\x89PNG"), "not a PNG");

    let shot = kit
        .json(
            "browser_screenshot",
            json!({"url": page.url(), "outputPath": "shots/second.png", "fullPage": true,
                   "timeoutSecs": 60}),
        )
        .await;
    assert_eq!(shot["title"], "Nebula test page");
    assert!(kit.exists("shots/second.png"));
    let err = kit
        .err(
            "browser_screenshot",
            json!({"url": page.url(), "outputPath": "shots/second.png", "timeoutSecs": 60}),
        )
        .await;
    assert!(err.starts_with("[invalid_arguments]") && err.contains("overwrite"), "{err}");

    // Navigating straight to the refused host fails as a policy refusal.
    let err = kit
        .err(
            "browser_capture",
            json!({"url": format!("http://localhost:{secret_port}/secret"), "timeoutSecs": 60}),
        )
        .await;
    assert!(err.starts_with("[network_not_allowed]"), "{err}");
    assert!(secret.seen().is_empty());
}
