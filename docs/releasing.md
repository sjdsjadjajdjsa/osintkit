# Releasing

PyPI files are immutable, so every release needs a new version. The pipeline refuses a tag that
does not match `osintkit.__version__`.

1. Make sure `main` is green and the tree is clean.
2. Bump `version` in `pyproject.toml` and `__version__` in `src/osintkit/__init__.py`.
3. Move the `Unreleased` entries in `CHANGELOG.md` under the new version with today's date.
4. Commit as `chore: release X.Y.Z`, push, and confirm CI is green.
5. Tag and push:
   ```bash
   git tag -a vX.Y.Z -m "osintkit X.Y.Z"
   git push origin vX.Y.Z
   ```
6. `release.yml` builds, checksums, publishes the GitHub release, and dispatches `publish.yml`
   (a `GITHUB_TOKEN` release does not fire release events by itself).
7. Confirm the PyPI JSON endpoint answers for the new version, then edit the release title and
   notes — the auto-generated ones are just commit subjects.
8. Install from PyPI in a clean venv and run `--version` plus one offline lookup.

If the publish job fails, the release is already public: fix forward with a patch version rather
than deleting the tag, unless the failure happened before the upload.

`PUBLISH_TO_PYPI=false` disables the PyPI dispatch for a GitHub-only release.

Container images publish to GHCR on `main` and on tags, but the package starts **private**; set
its visibility under the package settings when it should be pullable.
