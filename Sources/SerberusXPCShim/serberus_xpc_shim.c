#include "serberus_xpc_shim.h"

// Stable libxpc SPI — exported by the system, omitted from the public header.
extern void xpc_connection_get_audit_token(xpc_connection_t connection,
                                           audit_token_t *token);

bool serberus_xpc_connection_copy_audit_token(xpc_connection_t connection,
                                              audit_token_t *token) {
    if (connection == NULL || token == NULL) {
        return false;
    }
    xpc_connection_get_audit_token(connection, token);
    return true;
}

uid_t serberus_audit_token_euid(audit_token_t token) {
    return audit_token_to_euid(token);
}
