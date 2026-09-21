### Fixed

- **README's Architecture tree listed two files that no longer exist** (#54).
  `pkg/noiseproto/bootstrap/fips_policy.go` and `fips_policy_fips.go` were
  deleted by #51, which replaced the build-tag suite policy with the runtime
  probe that now lives in `negotiation.go`, but the tree kept an entry for each
  — nothing else in the repository referenced either name. Both entries are
  gone and `negotiation.go`'s description names the probe alongside the
  per-connection suite selection, so the file the policy moved into is the file
  the tree credits with it. The tree also gains `changelog.d/`, present since
  #51 and absent from the listing; every other entry was checked against
  `git ls-files` and already matched. Documentation only: no exported surface,
  behaviour, or build output changes.
