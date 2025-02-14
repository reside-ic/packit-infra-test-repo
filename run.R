get_packit_audience <- function(url) {
  response <- httr2::request(url) |>
    httr2::req_url_path_append("packit/api/auth/login/service/audience") |>
    httr2::req_perform() |>
    httr2::resp_body_json()
  response$audience
}

check_audience <- function(url) {
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
  expected_audience <- get_packit_audience(url)
  if (expected_audience != url) {
    cli::cli_warn(
      paste("The Packit URL is {.url {url}}, but the server is expecting",
            "the audience to be {.url {expected_audience}}. Authentication is",
            "likely to fail."))
  }
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

get_packit_token_service <- function(url, token) {
  response <- httr2::request(url) |>
    httr2::req_url_path_append("packit/api/auth/login/service") |>
    httr2::req_body_json(list(token = token)) |>
    httr2::req_perform() |>
    httr2::resp_body_json()
  response$token
}

get_packit_token_api <- function(url, token) {
  response <- httr2::request(url) |>
    httr2::req_url_path_append("packit/api/auth/login/api") |>
    httr2::req_body_json(list(token = token)) |>
    httr2::req_perform() |>
    httr2::resp_body_json()
  response$token
}

task_run <- function(url, token, branch, hash, name) {
  req <- httr2::request(url) |>
    httr2::req_url_path_append("packit/api/runner/run") |>
    httr2::req_auth_bearer_token(token) |>
    httr2::req_body_json(list(name = name, branch = branch, hash = hash))

  task <- httr2::req_perform(req) |>
    httr2::resp_body_json()

  task$taskId
}

task_status <- function(url, token, task_id, include_logs = FALSE) {
  req <- httr2::request(url) |>
    httr2::req_auth_bearer_token(token) |>
    httr2::req_template("packit/api/runner/status/{task_id}") |>
    httr2::req_url_query(includeLogs = include_logs)

  httr2::req_perform(req) |>
    httr2::resp_body_json()
}

task_wait <- function(url, token, task_id) {
  while (TRUE) {
    status <- task_status(url, token, task_id)
    if (status$status != "RUNNING") {
      return (invisible(status))
    }
    Sys.sleep(1)
  }
}

authenticate <- function(url) {
  packit_token <- Sys.getenv("PACKIT_TOKEN", NA)
  if (!is.na(packit_token)) {
    return (packit_token)
  }

  github_token <- Sys.getenv("GITHUB_TOKEN", NA)
  if (!is.na(github_token)) {
    return(get_packit_token_api(url, github_token))
  }

  check_audience(url)
  github_token <- get_oidc_token(url)
  get_packit_token_service(url, github_token)
}

download_packet <- function(url, token, packet_id, path) {
  metadata <- httr2::request(url) |>
    httr2::req_auth_bearer_token(token) |>
    httr2::req_template("packit/api/outpack/metadata/{packet_id}/json") |>
    httr2::req_perform() |>
    httr2::resp_body_json()

  for (file in metadata$data$files) {
    out <- fs::path(path, file$path)
    fs::dir_create(dirname(out))
    httr2::request(url) |>
      httr2::req_auth_bearer_token(token) |>
      httr2::req_template("packit/api/outpack/file/{hash}", hash = file$hash) |>
      httr2::req_perform(out)
  }
}

run <- function(url, token, ref_name, sha, entry) {
  if (!is.na(Sys.getenv("CI", NA))) {
    cli::cli_text("::group::Running {entry$name}")
    withr::defer(cli::cli_text("::endgroup::"))
  }
  cli::cli_rule("Running {entry$name}")

  task_id <- task_run(url, token, ref_name, sha, entry$name)
  task_wait(url, token, task_id)
  status <- task_status(url, token, task_id, include_logs = TRUE)

  cli::cli_verbatim(unlist(status$logs))

  if (status$status != "COMPLETE") {
    cli::cli_abort("Task failed")
  } else {
    packet_url <- glue::glue("{url}/{status$packetGroupName}/{status$packetId}")
    cli::cli_alert_success("Report ran successfully and produced packet {status$packetId}")
    cli::cli_alert_info("Packet is available at {.url {packet_url}}")
  }

  if (!is.null(entry$export)) {
    download_packet(url, token, status$packetId, entry$export)
  }
}

main <- function(args = commandArgs(trailingOnly = TRUE)) {
  url <- args[[1]]
  input <- args[[2]]

  ref_name <- Sys.getenv("GITHUB_REF_NAME", "main")
  sha <- Sys.getenv("GITHUB_SHA", "HEAD")

  token <- authenticate(url)
  data <- yaml::read_yaml(file = input)

  for (entry in data) {
    run(url, token, ref_name, sha, entry)
  }
}

main()
