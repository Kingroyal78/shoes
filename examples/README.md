# Legacy Local-Engine Examples

Files in this directory exercise the generic local YAML engine inherited by
`shoes`, including client/outbound chains, utility listeners, TUN, and protocol
combinations that are not part of the dedicated V2Board node-server product.

They are retained for development and regression testing. Do not use them as a
production support matrix or as V2Board deployment guidance.

For the supported server configuration, use:

- `../config/config.yml.example`
- `../CONFIG.md`
- `../docs/v2board-runtime-support.md`
- `../docs/v2board-alignment-audit.md`

Where an example contains a client and a server, only its server-side code path
may be relevant to the server audit, and only when the same behavior is exposed
and covered through the V2Board runtime.
