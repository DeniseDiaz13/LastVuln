[Español](roadmap.es.md)

# Future Improvements

## Support for more dependency files

Add support for new dependency file formats such as:
- `yarn.lock` (Node.js)
- `Cargo.lock` (Rust)
- `go.mod` (Go)

## Performance improvements

- For large-scale scanning, add an additional cache based on `ghsa_id` to further 
reduce response times during package searches and dependency scans.

## Continuous Integration

- Run code quality checks on every change.
- Generate automated test reports.
- Add type checking with mypy (to detect type errors in Python).
- Add linting with ruff (to maintain clean and consistent code).

## Distribution

- Create an installable package through PyPI.
- Create release binaries.
- Package the application for Arch Linux installation through an AUR helper.

