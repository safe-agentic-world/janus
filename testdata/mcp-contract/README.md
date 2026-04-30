# MCP Reference Contract Fixtures

`reference-servers.json` pins the official MCP reference packages covered by the Nomos contract suite.

The Go contract tests do not vendor or download those package payloads. They run deterministic offline fixtures that model the protocol surfaces Nomos must govern for each pinned reference:

- tools
- resources
- prompts
- sampling where supported
- stdio and Streamable HTTP upstream transports

Update the pinned package version and integrity together when refreshing reference coverage.
