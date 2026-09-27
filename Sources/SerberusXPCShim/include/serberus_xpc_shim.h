#ifndef SERBERUS_XPC_SHIM_H
#define SERBERUS_XPC_SHIM_H

#include <xpc/xpc.h>
#include <mach/message.h> // audit_token_t
#include <bsm/libbsm.h>   // audit_token_to_euid
#include <sys/types.h>    // uid_t
#include <stdbool.h>

/// Copies the audit token of a low-level XPC peer connection.
///
/// Audit tokens are the only TOCTOU-safe peer identity for XPC.
/// The underlying `xpc_connection_get_audit_token` is a stable libxpc SPI
/// (exported, just not in the public headers); it is the standard mechanism
/// privileged helpers use to identify low-level peers, since NSXPC's public
/// `auditToken` is unavailable when speaking raw dictionaries to a C client.
///
/// Returns false (leaving *token untouched) for NULL arguments.
bool serberus_xpc_connection_copy_audit_token(xpc_connection_t connection,
                                              audit_token_t *token);

/// Effective UID of an audit-token peer, via the official libbsm accessor.
uid_t serberus_audit_token_euid(audit_token_t token);

#endif /* SERBERUS_XPC_SHIM_H */
