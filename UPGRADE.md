# Upgrade Guide

## XRAI maintained fork

Require the Composer-compatible `v1.11.1-patch3` tag for the
`v1.11.1-xrai.3` maintained release.

Applications that require connection authority set
`options.xrai_connection_authority` to `true` for the Reverb application and
set `options.allowed_client_events` to the exact list of permitted client event
names. Each physical Pusher connection must complete `pusher:signin` before it
can subscribe to a protected channel, publish a client event, or receive a
protected delivery.

The application updates or revokes a signed connection lease through the
standard authenticated Pusher HTTP API. Lease updates use
`POST /apps/{appId}/xrai/connection-leases`; revocation uses the standard user
termination route with the opaque connection principal as `{userId}`. Scaled
servers apply the same signed controls through Redis pub/sub.

Direct, unscaled lease updates return the number of matching connections in
`connections_updated`. Scaled updates acknowledge publication because each
node applies the command independently.

Deployments that restart Reverb through a process supervisor or container
orchestrator should set `REVERB_RESTART_POLLING=false`. This prevents the
framework cache used by `reverb:restart` from blocking the socket event loop
during an outage. Leave polling enabled when the cache-backed
`reverb:restart` command is the deployment's process-control mechanism.

Enabling this option requires a compatible user-auth endpoint and lease-control
client. Applications that do not enable it retain the upstream channel,
client-event, delivery, and user-termination behavior. The lease route returns
404 for those applications.
