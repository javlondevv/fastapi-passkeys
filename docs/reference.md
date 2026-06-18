# API reference

Auto-generated from the source docstrings. Everything below is part of the public,
supported API and is importable from the top-level `fastapi_passkeys` package.

## Facade (Layer A)

::: fastapi_passkeys.Passkeys
    options:
      show_root_heading: true
      heading_level: 3

::: fastapi_passkeys.PasskeyConfig
    options:
      show_root_heading: true
      heading_level: 3

## Services (Layer B)

::: fastapi_passkeys.RegistrationService
    options:
      show_root_heading: true
      heading_level: 3
      members_order: source

::: fastapi_passkeys.AuthenticationService
    options:
      show_root_heading: true
      heading_level: 3
      members_order: source

## Domain models

::: fastapi_passkeys.PasskeyUser
    options:
      show_root_heading: true
      heading_level: 3

::: fastapi_passkeys.Credential
    options:
      show_root_heading: true
      heading_level: 3

::: fastapi_passkeys.AuthenticationResult
    options:
      show_root_heading: true
      heading_level: 3

## Storage protocols

::: fastapi_passkeys.CredentialRepository
    options:
      show_root_heading: true
      heading_level: 3

::: fastapi_passkeys.ChallengeStore
    options:
      show_root_heading: true
      heading_level: 3

## Audit

::: fastapi_passkeys.AuditEvent
    options:
      show_root_heading: true
      heading_level: 3

::: fastapi_passkeys.AuditSink
    options:
      show_root_heading: true
      heading_level: 3

## Exceptions

::: fastapi_passkeys.exceptions
    options:
      show_root_heading: false
      heading_level: 3
      members_order: source
      filters: ["!^_"]
