# HIDM Go Proof of Concept

This module implements the Healthcare-specific Identity Management (HIDM) proof of concept in Go.

It includes:

- Patient credential issuance using BBS+
- Patient-held credential storage
- Selective-disclosure verification
- Pseudonym-token issuance
- Appointment-token issuance
- Appointment booking
- In-person identity-verification workflow
- Performance measurement commands

## Requirements

- Go 1.26 or later

## Install dependencies

```bash
go mod download
```

## Run tests

```bash
go test ./...
```

## Run the demonstration

```bash
go run ./cmd/issue
```

## Run measurements

```bash
go run ./cmd/measure-issuance -iterations 30
go run ./cmd/measure-pseudonym-token-issuance -iterations 30
go run ./cmd/measure-appointment-token-issuance -iterations 30
go run ./cmd/measure-appointment-booking -iterations 30
go run ./cmd/measure-in-person-identity-verification -iterations 30
```

Generated measurement results should be treated as experimental artifacts and should not contain real patient information.

## Security note

This is a research proof of concept. It is not intended for production healthcare deployment. Real deployments require secure key storage, authenticated services, durable replay protection, protected audit logs, governed biometric processing, and formal security review.
```
