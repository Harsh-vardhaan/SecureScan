## Scope and purpose

Describe the problem and the focused change made to address it.

## Verification

List the safe tests and checks you ran.

## Checklist

- [ ] The change has a clear, focused purpose.
- [ ] Relevant unit tests pass and scanner calls are mocked.
- [ ] No real Nmap scan or unauthorized target interaction was performed.
- [ ] No secret, database, generated report, log, or private target data is included.
- [ ] Documentation was updated where behavior, setup, or limitations changed.
- [ ] The fixed scanner and authorized-use boundaries are preserved.
- [ ] New or updated screenshots are sanitized and contain only synthetic data.
- [ ] `git diff --check` passes.

## Security and scope impact

Explain any effect on target validation, scanner boundaries, stored data,
reporting, deployment, or user-facing security guidance. Write `None` if there
is no security or scope impact.
