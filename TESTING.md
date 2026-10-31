# Testing

Tests live in the `IdentityServer.Tests` project (xUnit). Folders separate test kinds and mirror the layout
of the Web API project:

```text
IdentityServer.Tests/
└── Unit/          # unit tests: one class under test, no HTTP pipeline
    ├── Entities/
    └── Services/
```

Unit tests that need a database use SQLite in-memory (see `Unit/Services/TokenServiceFixture.cs`), so no
SQL Server, Docker or `appsettings*.json` is required to run them.

All commands below are run from the repository root.

## Running tests

```bash
dotnet test
```

Run a subset with `--filter`:

```bash
# one folder / namespace
dotnet test --filter "FullyQualifiedName~IdentityServer.Tests.Unit.Services"

# one test class
dotnet test --filter "FullyQualifiedName~TokenServiceRefreshTokenTests"

# one test
dotnet test --filter "FullyQualifiedName~TokenServiceRefreshTokenTests.RefreshTokens_SameOldTokenTwice_SecondCallReturnsNullAndStoresNothing"
```

## Code coverage

Coverage is collected by `Microsoft.CodeCoverage`, which comes with `Microsoft.NET.Test.Sdk`; no extra
package is needed in the test project.

### 1. Collect coverage

```bash
rm -rf TestResults
dotnet test --collect "Code Coverage;Format=cobertura" --results-directory ./TestResults
```

In PowerShell replace the first line with `Remove-Item -Recurse -Force TestResults -ErrorAction Ignore`.

The report is written to `TestResults/<guid>/*.cobertura.xml`. `TestResults/` is git-ignored.

Removing `TestResults` first matters: every run adds a new `<guid>` folder, and the report step below would
merge all of them.

Without `;Format=cobertura` the collector writes a binary `.coverage` file, which only Visual Studio
Enterprise can open.

### 2. Build an HTML report

Install ReportGenerator once:

```bash
dotnet tool install -g dotnet-reportgenerator-globaltool
```

Generate the report:

```bash
reportgenerator "-reports:TestResults/**/*.cobertura.xml" "-targetdir:TestResults/coverage-report" "-reporttypes:Html" "-assemblyfilters:-IdentityServer.Tests"
```

Open `TestResults/coverage-report/index.html`.

`-assemblyfilters:-IdentityServer.Tests` excludes the test assembly itself; otherwise its own 100% coverage
inflates the totals.

Keep every argument in quotes. PowerShell splits an unquoted argument that starts with `-` at the first dot,
so `-assemblyfilters:-IdentityServer.Tests` arrives as `-assemblyfilters:-IdentityServer` and `.Tests`:
the filter then excludes the Web API project and the report shows only the tests.

To get a short summary in the terminal instead of HTML, use `-reporttypes:TextSummary` and read
`TestResults/coverage-report/Summary.txt`.

### Reading the numbers

- Async methods are compiled into separate state-machine classes, so the raw Cobertura XML reports a class
  such as `TokenService` partly under generated names. The HTML report merges them back into the source
  class; use it rather than the XML.
- The overall percentage of the `IdentityServer` assembly is low while only `TokenService` and
  `RefreshToken` are covered; check the per-class numbers for the code under test.
