# Sample output

Trimmed `--markdown` export from a live run against a placeholder address. Real runs list
every collector, including the ones that failed or were skipped.

```markdown
# OSINT report: test@example.com

- Type: `email`
- Risk: **high**

## Summary

The supplied breach index reports that test@example.com appears in 80 separate breach
collections. Confirmed findings are limited to that membership: every entry carries a null
date and an empty exposed-data list, so neither the exposure date nor the fields exposed can
be verified from this data. The high rating is driven by the breadth of the exposure surface
rather than by confirmed credential leaks. No accounts, handles, or hostnames were returned.

## Breaches

| Breach | Date | Exposed data | Source |
| --- | --- | --- | --- |
| Cit0day | unknown | undisclosed | xposedornot |
| Collection-1 | unknown | undisclosed | xposedornot |
| OGusers-2020 | unknown | undisclosed | xposedornot |
| LinkedIn | unknown | undisclosed | xposedornot |
| Twitter | unknown | undisclosed | xposedornot |

## Infrastructure and attack surface

- Only one source was queried: the breach index. It returned status ok with no note.
- Every returned record has a null date and no data types. That is a reporting gap in the
  source, not evidence that only non-sensitive fields were exposed.
- No account handles or subdomains were returned, so those sections are empty because nothing
  was found, not because those checks cleared.

## Recommendations

- Re-query with an HIBP key to get dated incidents and exposed field names.
- Treat reuse of this address as risky until the credential-bearing subset is confirmed.
- Turn on 2FA anywhere the address is used as a login.
```

The same data as JSON (`--json`) or as colour-coded terminal output (default).
