//! GitHub tools: the REST API, with the operator's token.
//!
//! Every request goes to `[github] api_url` and nowhere else: tools build the
//! path from checked pieces, and `github_request` accepts a path, never a
//! URL. The token is attached by this module only; a redirect to another
//! origin is followed without it (see `nebula_mcp_core::net`).

use std::sync::Arc;

use nebula_mcp_core::args::Args;
use nebula_mcp_core::net::HttpRequest;
use nebula_mcp_core::schema::ObjectSchema;
use nebula_mcp_core::tool::Content;
use nebula_mcp_core::{Category, Effects, Gate, Result, Tool, ToolContext, ToolError, ToolOutput};
use serde_json::{json, Map, Value};

use crate::common::{clip, handler, spec, tool, SpecExt};

const API_VERSION: &str = "2022-11-28";
const READ: Effects = Effects::read_only().network();
const WRITE: Effects = Effects::writes().network();

/// How a field of an API object appears in a tool result.
#[derive(Clone, Copy)]
enum Kind {
    Text,
    OptText,
    Int,
    Flag,
    /// An array of objects, reduced to their `name`s.
    Names,
}

/// Result field: name, JSON pointer into the API object, kind, description.
type Field = (&'static str, &'static str, Kind, &'static str);

const PULL: &[Field] = &[
    ("number", "/number", Kind::Int, "Pull request number."),
    ("title", "/title", Kind::Text, "Title."),
    ("state", "/state", Kind::Text, "open or closed."),
    ("draft", "/draft", Kind::Flag, "Whether it is a draft."),
    (
        "author",
        "/user/login",
        Kind::OptText,
        "Login of the author.",
    ),
    ("head", "/head/ref", Kind::Text, "Branch with the changes."),
    ("base", "/base/ref", Kind::Text, "Branch it targets."),
    ("url", "/html_url", Kind::Text, "Web page."),
    (
        "updatedAt",
        "/updated_at",
        Kind::OptText,
        "Last update, ISO 8601.",
    ),
];
const ISSUE: &[Field] = &[
    ("number", "/number", Kind::Int, "Issue number."),
    ("title", "/title", Kind::Text, "Title."),
    ("state", "/state", Kind::Text, "open or closed."),
    (
        "author",
        "/user/login",
        Kind::OptText,
        "Login of the author.",
    ),
    ("labels", "/labels", Kind::Names, "Label names."),
    ("comments", "/comments", Kind::Int, "Number of comments."),
    ("url", "/html_url", Kind::Text, "Web page."),
    (
        "updatedAt",
        "/updated_at",
        Kind::OptText,
        "Last update, ISO 8601.",
    ),
];
const RELEASE: &[Field] = &[
    ("id", "/id", Kind::Int, "Release id."),
    ("tag", "/tag_name", Kind::Text, "Tag the release points at."),
    ("name", "/name", Kind::OptText, "Release title."),
    ("draft", "/draft", Kind::Flag, "Whether it is unpublished."),
    (
        "prerelease",
        "/prerelease",
        Kind::Flag,
        "Whether it is a prerelease.",
    ),
    (
        "publishedAt",
        "/published_at",
        Kind::OptText,
        "Publication time, ISO 8601.",
    ),
    ("url", "/html_url", Kind::Text, "Web page."),
];
const RUN: &[Field] = &[
    ("id", "/id", Kind::Int, "Run id."),
    ("name", "/name", Kind::OptText, "Workflow name."),
    (
        "status",
        "/status",
        Kind::OptText,
        "queued, in_progress or completed.",
    ),
    (
        "conclusion",
        "/conclusion",
        Kind::OptText,
        "success, failure, cancelled, ... once completed.",
    ),
    (
        "branch",
        "/head_branch",
        Kind::OptText,
        "Branch the run is for.",
    ),
    ("event", "/event", Kind::Text, "What triggered it."),
    ("sha", "/head_sha", Kind::Text, "Commit it ran on."),
    ("url", "/html_url", Kind::Text, "Web page."),
    (
        "createdAt",
        "/created_at",
        Kind::OptText,
        "Start time, ISO 8601.",
    ),
];
const BRANCH: &[Field] = &[
    ("name", "/name", Kind::Text, "Branch name."),
    ("sha", "/commit/sha", Kind::Text, "Commit at its tip."),
    (
        "protected",
        "/protected",
        Kind::Flag,
        "Whether branch protection applies.",
    ),
];
const LABEL: &[Field] = &[
    ("name", "/name", Kind::Text, "Label name."),
    ("color", "/color", Kind::Text, "Hex colour without '#'."),
    ("description", "/description", Kind::OptText, "Description."),
];
const CREATED: &[Field] = &[
    ("number", "/number", Kind::Int, "Number of the new item."),
    ("url", "/html_url", Kind::Text, "Web page."),
];

fn item_schema(fields: &[Field]) -> ObjectSchema {
    fields.iter().fold(
        ObjectSchema::open(),
        |s, (name, _, kind, help)| match kind {
            Kind::Text => s.string(name, help, true),
            Kind::OptText => s.nullable_string(name, help, true),
            Kind::Int => s.integer(name, help, true),
            Kind::Flag => s.boolean(name, help, true),
            Kind::Names => s.string_array(name, help, true),
        },
    )
}

fn item(fields: &[Field], from: &Value) -> Value {
    let mut out = Map::new();
    for (name, pointer, kind, _) in fields {
        let found = from.pointer(pointer);
        let value = match kind {
            Kind::Text => json!(found.and_then(Value::as_str).unwrap_or_default()),
            Kind::OptText => found
                .and_then(Value::as_str)
                .map_or(Value::Null, |s| json!(s)),
            Kind::Int => json!(found.and_then(Value::as_i64).unwrap_or_default()),
            Kind::Flag => json!(found.and_then(Value::as_bool).unwrap_or_default()),
            Kind::Names => json!(found
                .and_then(Value::as_array)
                .map(|a| a
                    .iter()
                    .filter_map(|l| l.get("name").and_then(Value::as_str))
                    .collect::<Vec<_>>())
                .unwrap_or_default()),
        };
        out.insert((*name).to_string(), value);
    }
    Value::Object(out)
}

fn repo_schema() -> ObjectSchema {
    ObjectSchema::new()
        .string(
            "owner",
            "User or organisation that owns the repository.",
            true,
        )
        .string("repo", "Repository name.", true)
}

fn paged(schema: ObjectSchema) -> ObjectSchema {
    schema
        .integer_range("perPage", "Items per page (default 30).", 1, 100, false)
        .integer_min("page", "Page number, starting at 1.", 1, false)
}

fn list_output(key: &str, fields: &[Field]) -> Value {
    ObjectSchema::open()
        .object_array(
            key,
            "One entry per item, in API order.",
            item_schema(fields),
            true,
        )
        .build()
}

/// The `github` tools.
#[allow(clippy::too_many_lines)]
pub(crate) fn tools() -> Vec<Arc<dyn Tool>> {
    let c = Category::Github;
    let state = |s: ObjectSchema| {
        s.string_enum(
            "state",
            "Which to list (default open).",
            &["open", "closed", "all"],
            false,
        )
    };
    vec![
        tool(
            spec(
                "github_pr_list",
                c,
                "List pull requests",
                "Pull requests of a repository, newest first.",
                paged(state(repo_schema())).build(),
                READ,
            )
            .returns(list_output("pullRequests", PULL)),
            handler!(pr_list),
        ),
        tool(
            spec(
                "github_pr_create",
                c,
                "Open pull request",
                "Open a pull request from `head` into `base`. Push the branch first (git_push).",
                repo_schema()
                    .string("title", "Title.", true)
                    .string(
                        "head",
                        "Branch with the changes; `user:branch` for a fork.",
                        true,
                    )
                    .string("base", "Branch to merge into.", true)
                    .string("body", "Description, Markdown.", false)
                    .boolean("draft", "Open as a draft.", false)
                    .build(),
                WRITE,
            )
            .returns(item_schema(CREATED).build()),
            handler!(pr_create),
        ),
        tool(
            spec(
                "github_review_create",
                c,
                "Review pull request",
                "Submit a review on a pull request: approve it, request changes or comment.",
                repo_schema()
                    .integer_min("pull", "Pull request number.", 1, true)
                    .string_enum(
                        "event",
                        "The verdict.",
                        &["APPROVE", "REQUEST_CHANGES", "COMMENT"],
                        true,
                    )
                    .string("body", "Review text; required unless approving.", false)
                    .build(),
                WRITE,
            )
            .returns(
                ObjectSchema::open()
                    .integer("id", "Review id.", true)
                    .string("state", "State of the review.", true)
                    .string("url", "Web page.", true)
                    .build(),
            ),
            handler!(review_create),
        ),
        tool(
            spec(
                "github_issue_list",
                c,
                "List issues",
                "Issues of a repository, newest first. Pull requests are not included.",
                paged(state(repo_schema()))
                    .string_array("labels", "Only issues carrying all of these labels.", false)
                    .build(),
                READ,
            )
            .returns(list_output("issues", ISSUE)),
            handler!(issue_list),
        ),
        tool(
            spec(
                "github_issue_create",
                c,
                "Open issue",
                "Open an issue in a repository and return its number and web page.",
                repo_schema()
                    .string("title", "Title.", true)
                    .string("body", "Description, Markdown.", false)
                    .string_array("labels", "Labels to apply; they must exist.", false)
                    .build(),
                WRITE,
            )
            .returns(item_schema(CREATED).build()),
            handler!(issue_create),
        ),
        tool(
            spec(
                "github_labels_list",
                c,
                "List labels",
                "Labels defined in a repository.",
                paged(repo_schema()).build(),
                READ,
            )
            .returns(list_output("labels", LABEL)),
            handler!(labels_list),
        ),
        tool(
            spec(
                "github_branch_list",
                c,
                "List branches",
                "Branches of a repository on GitHub, with the commit at each tip.",
                paged(repo_schema()).build(),
                READ,
            )
            .returns(list_output("branches", BRANCH)),
            handler!(branch_list),
        ),
        tool(
            spec(
                "github_release_list",
                c,
                "List releases",
                "Releases of a repository, newest first.",
                paged(repo_schema()).build(),
                READ,
            )
            .returns(list_output("releases", RELEASE)),
            handler!(release_list),
        ),
        tool(
            spec(
                "github_release_create",
                c,
                "Create release",
                "Create a release for a tag. The tag is created from `target` when it does not \
                 exist yet.",
                repo_schema()
                    .string("tag", "Tag name, for example v1.2.0.", true)
                    .string("name", "Release title (default: the tag).", false)
                    .string("body", "Release notes, Markdown.", false)
                    .string(
                        "target",
                        "Branch or commit to tag when the tag is new.",
                        false,
                    )
                    .boolean("draft", "Create it unpublished.", false)
                    .boolean("prerelease", "Mark it as a prerelease.", false)
                    .build(),
                WRITE,
            )
            .returns(
                ObjectSchema::open()
                    .integer("id", "Release id.", true)
                    .string("url", "Web page.", true)
                    .build(),
            ),
            handler!(release_create),
        ),
        tool(
            spec(
                "github_workflow_runs",
                c,
                "List workflow runs",
                "Recent GitHub Actions runs of a repository with their status and conclusion.",
                paged(repo_schema())
                    .string("branch", "Only runs for this branch.", false)
                    .build(),
                READ,
            )
            .returns(list_output("runs", RUN)),
            handler!(workflow_runs),
        ),
        tool(
            spec(
                "github_fork",
                c,
                "Fork repository",
                "Fork a repository into the token's account, or into `organization`.",
                repo_schema()
                    .string("organization", "Organisation to fork into.", false)
                    .build(),
                WRITE,
            )
            .returns(
                ObjectSchema::open()
                    .string("fullName", "owner/name of the fork.", true)
                    .string("url", "Web page.", true)
                    .build(),
            ),
            handler!(fork),
        ),
        tool(
            spec(
                "github_request",
                c,
                "GitHub API request",
                "Call any GitHub REST endpoint not covered by the other tools. `path` is the \
                 part after the API host, for example /repos/OWNER/REPO/issues/5/comments; a \
                 full URL is refused. DELETE is destructive. Returns the JSON response.",
                ObjectSchema::new()
                    .string_enum(
                        "method",
                        "HTTP method (default GET).",
                        &["GET", "POST", "PATCH", "PUT", "DELETE"],
                        false,
                    )
                    .string("path", "Endpoint path starting with '/'.", true)
                    .string_map("query", "Query parameters.", false)
                    .prop(
                        "body",
                        json!({"type": "object", "description": "JSON request body."}),
                        false,
                    )
                    .build(),
                WRITE.destructive(Gate::Sometimes),
            ),
            handler!(request),
        ),
    ]
}

// ---------------------------------------------------------------------------
// The API client
// ---------------------------------------------------------------------------

fn token(ctx: &ToolContext) -> Option<String> {
    let name = ctx.config().github.token_env.as_str();
    let read = |n: &str| {
        std::env::var(n)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    read(name).or_else(|| {
        if name == "GITHUB_TOKEN" {
            read("GH_TOKEN")
        } else {
            None
        }
    })
}

fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// An owner or repository name as a path segment.
fn segment<'a>(value: &'a str, what: &str) -> Result<&'a str> {
    let ok = !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(value)
    } else {
        Err(ToolError::invalid(format!(
            "`{what}` must be a GitHub name (letters, digits, '-', '_' and '.')"
        )))
    }
}

fn repo_path(a: &Args<'_>) -> Result<String> {
    Ok(format!(
        "/repos/{}/{}",
        segment(a.str("owner")?, "owner")?,
        segment(a.str("repo")?, "repo")?
    ))
}

struct Response {
    status: u16,
    body: Vec<u8>,
    truncated: bool,
}

/// Send one request to the configured API.
async fn send(
    ctx: &ToolContext,
    method: &str,
    path: &str,
    query: &[(String, String)],
    body: Option<&Value>,
) -> Result<Response> {
    let token = token(ctx);
    if method != "GET" && token.is_none() {
        return Err(ToolError::denied(format!(
            "this needs a GitHub token. The operator provides it in the server's environment \
             variable {}.",
            ctx.config().github.token_env
        )));
    }
    let mut url = format!("{}{path}", ctx.config().github.api_url);
    for (i, (key, value)) in query.iter().enumerate() {
        url.push(if i == 0 { '?' } else { '&' });
        url.push_str(&encode(key));
        url.push('=');
        url.push_str(&encode(value));
    }
    let mut req = HttpRequest::new(method, url);
    req.timeout = ctx.timeout(None);
    req.max_redirects = 3;
    req.max_body_bytes = ctx.max_output_bytes();
    req.headers = vec![
        ("Accept".into(), "application/vnd.github+json".into()),
        ("X-GitHub-Api-Version".into(), API_VERSION.into()),
        (
            "User-Agent".into(),
            concat!("nebula-mcp/", env!("CARGO_PKG_VERSION")).into(),
        ),
    ];
    if let Some(token) = token {
        req.headers
            .push(("Authorization".into(), format!("Bearer {token}")));
    }
    if let Some(body) = body {
        req.headers
            .push(("Content-Type".into(), "application/json".into()));
        req.body = Some(serde_json::to_vec(body)?);
    }
    let response = ctx.net()?.http(req).await?;
    Ok(Response {
        status: response.status,
        body: response.body,
        truncated: response.truncated,
    })
}

/// Turn a non-2xx answer into an error that says what to change.
fn api_error(ctx: &ToolContext, status: u16, body: &[u8]) -> ToolError {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let mut message = parsed
        .as_ref()
        .and_then(|v| v.get("message"))
        .and_then(Value::as_str)
        .map_or_else(
            || String::from_utf8_lossy(body).into_owned(),
            str::to_string,
        );
    if let Some(errors) = parsed.as_ref().and_then(|v| v.get("errors")) {
        message.push_str(&format!(" {errors}"));
    }
    let message = clip(message.trim(), 1000);
    let env = &ctx.config().github.token_env;
    match status {
        401 => ToolError::denied(format!(
            "GitHub rejected the token (401 {message}). The operator sets it in {env}."
        )),
        403 | 429 => ToolError::denied(format!(
            "GitHub refused the request ({status} {message}). The token may lack the \
             permission, or the rate limit is exhausted."
        )),
        404 => ToolError::NotFound(format!(
            "GitHub answered 404 {message}: the item does not exist or the token cannot see it"
        )),
        422 => ToolError::invalid(format!("GitHub rejected the values (422 {message})")),
        _ => ToolError::Execution(format!("GitHub answered {status} {message}")),
    }
}

/// Send a request and return the parsed JSON of a 2xx answer.
async fn api(
    ctx: &ToolContext,
    method: &str,
    path: &str,
    query: &[(String, String)],
    body: Option<&Value>,
) -> Result<Value> {
    let response = send(ctx, method, path, query, body).await?;
    if !(200..300).contains(&response.status) {
        return Err(api_error(ctx, response.status, &response.body));
    }
    if response.truncated {
        return Err(ToolError::LimitExceeded(
            "the response is larger than the output limit; ask for fewer items with perPage"
                .to_string(),
        ));
    }
    if response.body.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&response.body)
        .map_err(|e| ToolError::Execution(format!("GitHub sent a response that is not JSON: {e}")))
}

fn page_query(a: &Args<'_>) -> Result<Vec<(String, String)>> {
    Ok(vec![
        ("per_page".to_string(), a.u64_or("perPage", 30)?.to_string()),
        ("page".to_string(), a.u64_or("page", 1)?.to_string()),
    ])
}

/// Fetch a list endpoint and reduce each element to `fields`.
async fn list(
    ctx: &ToolContext,
    path: &str,
    query: &[(String, String)],
    key: &str,
    fields: &[Field],
    keep: fn(&Value) -> bool,
) -> Result<ToolOutput> {
    let value = api(ctx, "GET", path, query, None).await?;
    // Some endpoints wrap the list in an object.
    let items = value
        .as_array()
        .or_else(|| value.get("workflow_runs").and_then(Value::as_array))
        .ok_or_else(|| ToolError::Execution("GitHub did not send a list".to_string()))?;
    let reduced: Vec<Value> = items
        .iter()
        .filter(|v| keep(v))
        .map(|v| item(fields, v))
        .collect();
    Ok(ToolOutput::json(json!({ key: reduced })))
}

fn any(_: &Value) -> bool {
    true
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

async fn pr_list(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mut query = vec![("state".to_string(), a.str_or("state", "open")?.to_string())];
    query.extend(page_query(&a)?);
    let path = format!("{}/pulls", repo_path(&a)?);
    list(ctx, &path, &query, "pullRequests", PULL, any).await
}

async fn issue_list(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mut query = vec![("state".to_string(), a.str_or("state", "open")?.to_string())];
    let labels = a.opt_str_array("labels")?;
    if !labels.is_empty() {
        query.push(("labels".to_string(), labels.join(",")));
    }
    query.extend(page_query(&a)?);
    let path = format!("{}/issues", repo_path(&a)?);
    // The issues endpoint also returns pull requests.
    list(ctx, &path, &query, "issues", ISSUE, |v| {
        v.get("pull_request").is_none()
    })
    .await
}

async fn labels_list(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let path = format!("{}/labels", repo_path(&a)?);
    list(ctx, &path, &page_query(&a)?, "labels", LABEL, any).await
}

async fn branch_list(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let path = format!("{}/branches", repo_path(&a)?);
    list(ctx, &path, &page_query(&a)?, "branches", BRANCH, any).await
}

async fn release_list(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let path = format!("{}/releases", repo_path(&a)?);
    list(ctx, &path, &page_query(&a)?, "releases", RELEASE, any).await
}

async fn workflow_runs(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mut query = page_query(&a)?;
    if let Some(branch) = a.opt_str("branch")? {
        query.push(("branch".to_string(), branch.to_string()));
    }
    let path = format!("{}/actions/runs", repo_path(&a)?);
    list(ctx, &path, &query, "runs", RUN, any).await
}

async fn pr_create(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let body = json!({
        "title": a.str("title")?,
        "head": a.str("head")?,
        "base": a.str("base")?,
        "body": a.str_or("body", "")?,
        "draft": a.bool_or("draft", false)?,
    });
    let path = format!("{}/pulls", repo_path(&a)?);
    let created = api(ctx, "POST", &path, &[], Some(&body)).await?;
    Ok(ToolOutput::json(item(CREATED, &created)))
}

async fn issue_create(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let body = json!({
        "title": a.str("title")?,
        "body": a.str_or("body", "")?,
        "labels": a.opt_str_array("labels")?,
    });
    let path = format!("{}/issues", repo_path(&a)?);
    let created = api(ctx, "POST", &path, &[], Some(&body)).await?;
    Ok(ToolOutput::json(item(CREATED, &created)))
}

async fn review_create(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let event = a.str("event")?;
    let text = a.str_or("body", "")?;
    if event != "APPROVE" && text.trim().is_empty() {
        return Err(ToolError::invalid(format!(
            "`body` is required for a {event} review"
        )));
    }
    let path = format!("{}/pulls/{}/reviews", repo_path(&a)?, a.u64("pull")?);
    let body = json!({"event": event, "body": text});
    let created = api(ctx, "POST", &path, &[], Some(&body)).await?;
    Ok(ToolOutput::json(item(
        &[
            ("id", "/id", Kind::Int, ""),
            ("state", "/state", Kind::Text, ""),
            ("url", "/html_url", Kind::Text, ""),
        ],
        &created,
    )))
}

async fn release_create(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let tag = a.str("tag")?;
    let mut body = json!({
        "tag_name": tag,
        "name": a.str_or("name", tag)?,
        "body": a.str_or("body", "")?,
        "draft": a.bool_or("draft", false)?,
        "prerelease": a.bool_or("prerelease", false)?,
    });
    if let Some(target) = a.opt_str("target")? {
        body["target_commitish"] = json!(target);
    }
    let path = format!("{}/releases", repo_path(&a)?);
    let created = api(ctx, "POST", &path, &[], Some(&body)).await?;
    Ok(ToolOutput::json(item(
        &[
            ("id", "/id", Kind::Int, ""),
            ("url", "/html_url", Kind::Text, ""),
        ],
        &created,
    )))
}

async fn fork(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let mut body = json!({});
    if let Some(org) = a.opt_str("organization")? {
        body["organization"] = json!(segment(org, "organization")?);
    }
    let path = format!("{}/forks", repo_path(&a)?);
    let created = api(ctx, "POST", &path, &[], Some(&body)).await?;
    Ok(ToolOutput::json(item(
        &[
            ("fullName", "/full_name", Kind::Text, ""),
            ("url", "/html_url", Kind::Text, ""),
        ],
        &created,
    )))
}

/// A path for `github_request`: it can only ever extend the API URL.
fn check_path(path: &str) -> Result<()> {
    let ok = path.starts_with('/')
        && !path.starts_with("//")
        && path.len() <= 2000
        && !path.contains(['?', '#', '\\'])
        && !path.chars().any(|c| c.is_control() || c.is_whitespace())
        && !path.split('/').any(|s| s == ".." || s == ".");
    if ok {
        Ok(())
    } else {
        Err(ToolError::invalid(
            "`path` must be an API path starting with '/', such as /repos/OWNER/REPO/issues, \
             without a host, '..', spaces, '?' or '#'. Put query parameters in `query`.",
        ))
    }
}

async fn request(ctx: &ToolContext, args: Value) -> Result<ToolOutput> {
    let a = Args::new(&args)?;
    let method = a
        .opt_enum("method", &["GET", "POST", "PATCH", "PUT", "DELETE"])?
        .unwrap_or("GET");
    let path = a.str("path")?;
    check_path(path)?;
    if method == "DELETE" {
        ctx.require_destructive("a DELETE request to GitHub")?;
    }
    let query = a.opt_string_map("query")?;
    let body = a.opt_value("body");
    if body.is_some() && method == "GET" {
        return Err(ToolError::invalid("a GET request takes no `body`"));
    }
    let response = send(ctx, method, path, &query, body).await?;
    if !(200..400).contains(&response.status) {
        return Err(api_error(ctx, response.status, &response.body));
    }
    let text = match serde_json::from_slice::<Value>(&response.body) {
        Ok(value) => serde_json::to_string_pretty(&value)?,
        Err(_) => String::from_utf8_lossy(&response.body).into_owned(),
    };
    let mut note = format!("[github_request: {} {}", response.status, method);
    if response.truncated {
        note.push_str("; the response was cut at the output limit");
    }
    note.push(']');
    let mut content = Vec::new();
    if !text.is_empty() {
        content.push(Content::Text(text));
    }
    content.push(Content::Text(note));
    Ok(ToolOutput {
        content,
        structured: None,
    })
}

#[cfg(test)]
#[path = "github_tests.rs"]
mod tests;
