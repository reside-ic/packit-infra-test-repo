PACKIT_URL <- "https://packit.dide.ic.ac.uk/reside"

get_packit_audience <- function(base_url) {
  response <- httr2::request(base_url) |>
    httr2::req_url_path_append("packit/api/auth/login/service/audience") |>
    httr2::req_perform() |>
    httr2::resp_body_json()
  response$audience
}

get_oidc_token <- function(audience) {
  url <- Sys.getenv("ACTIONS_ID_TOKEN_REQUEST_URL", NA)
  token <- Sys.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", NA)
  
  if (is.na(url) || is.na(token)) {
    cli::cli_abort(paste(
      "ID token environment variables are not set. Make sure you have added",
      "the {.code id-token: write} permission to your workflow."))
  }

  response <- httr2::request(url) |>
    httr2::req_url_query(audience=audience) |>
    httr2::req_auth_bearer_token(token) |>
    httr2::req_perform() |>
    httr2::resp_body_json()
  response$value
}

get_packit_token <- function(base_url, token) {
  response <- httr2::request(base_url) |>
    httr2::req_url_path_append("packit/api/auth/login/service") |>
    httr2::req_body_json(list(token = token)) |>
    httr2::req_perform() |>
    httr2::resp_body_json()
  response$token
}

task_run <- function(branch, hash, name) {
  req <- httr2::request(PACKIT_URL) |>
    httr2::req_url_path_append("packit/api/runner/run") |>
    httr2::req_auth_bearer_token(packit_token) |>
    httr2::req_body_json(list(name = name, branch = branch, hash = hash))

  task <- httr2::req_perform(req) |>
    httr2::resp_body_json()

  task$taskId
}

task_status <- function(task_id, include_logs = FALSE) {
  req <- httr2::request(PACKIT_URL) |>
    httr2::req_auth_bearer_token(packit_token) |>
    httr2::req_url_path_append("packit/api/runner/status", task_id) |>
    httr2::req_url_query(includeLogs = include_logs)

  httr2::req_perform(req) |>
    httr2::resp_body_json()
}

task_wait <- function(task_id) {
  while (TRUE) {
    status <- task_status(task_id)
    if (status$status != "RUNNING") {
      return (invisible(status))
    }
    Sys.sleep(1)
  }
}

# The server will match its configured audience against the one found in the
# token exactly. A mismatch could occur if, for example, the user provided a
# non-canonical URL that routes to the same place but isn't strictly equal
# (eg. using `https://hostname:443` instead of just `https://hostname`).
#
# It is tempting to just use the audience provided by the server instead of
# PACKIT_URL and not have to worry about it ever failing to match. If we did
# that though, a malicious server could present an arbitrary audience and use
# the token we give it to login to a completely different service on behalf on
# this action, and we do not want to allow that.
#
# This warning provides an easy diagnostic and resolution path for the benign
# case of a non-canonical URL, while avoiding the aforementioned pitfall.
expected_audience <- get_packit_audience(PACKIT_URL)
if (expected_audience != PACKIT_URL) {
  cli::cli_warn(
    paste("The Packit URL is {.url {PACKIT_URL}}, but the server is expecting",
          "the audience to be {.url {expected_audience}}. Authentication is",
          "likely to fail."))
}

github_token <- get_oidc_token(PACKIT_URL)
packit_token <- get_packit_token(PACKIT_URL, github_token)

ref_name <- Sys.getenv("GITHUB_REF_NAME", "main")
sha <- Sys.getenv("GITHUB_SHA", "HEAD")
name <- "incoming_data"

task_id <- task_run(ref_name, sha, name)
task_wait(task_id)
status <- task_status(task_id)
writeLines(unlist(status$logs))

if (status$status != "COMPLETE") {
  cli::cli_abort("Task failed")
}
