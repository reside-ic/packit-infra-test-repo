run <- function(client, ref_name, sha, entry) {
  if (!is.na(Sys.getenv("CI", NA))) {
    cli::cli_text("::group::Running {entry$name}")
    withr::defer(cli::cli_text("::endgroup::"))
  } else {
    cli::cli_rule("Running {entry$name}")
  }

  task_id <- task_submit(client, ref_name, sha, entry$name)
  task_wait(client, task_id)
  status <- task_status(client, task_id, include_logs = TRUE)

  cli::cli_verbatim(unlist(status$logs))

  if (status$status != "COMPLETE") {
    cli::cli_abort("Task failed")
  } else {
    packet_url <- glue::glue("{client$url}/{status$packetGroupName}/{status$packetId}")
    cli::cli_alert_success("Report ran successfully and produced packet {status$packetId}")
    cli::cli_alert_info("Packet is available at {.url {packet_url}}")
  }

  if (!is.null(entry$export)) {
    download_packet(client, status$packetId, entry$export)
  }
}

main <- function(args = commandArgs(trailingOnly = TRUE)) {
  url <- args[[1]]
  input <- args[[2]]

  ref_name <- Sys.getenv("GITHUB_REF_NAME", "main")
  sha <- Sys.getenv("GITHUB_SHA", "HEAD")

  client <- packit_login(url)
  data <- yaml::read_yaml(file = input)

  for (entry in data) {
    run(client, ref_name, sha, entry)
  }
}

main()
