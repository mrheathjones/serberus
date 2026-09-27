//
//  SerberusAuthShim.m
//  SerberusAuth  —  the production authorization mechanism bundle
//
//  Per-app identity enforcement for authURI rights (see
//  docs/authuri-identity-scoped-rules.md). authd's static rule schema has no
//  code-requirement key, so a rule alone cannot tell one caller from another;
//  a mechanism was meant to, using the creator-audit-token hint (the only
//  identity the decision used) and the client-pid hint (logged only).
//
//  Those hints are NOT trustworthy. authd merges the caller's
//  AuthorizationCreate / AuthorizationCopyRights environment into the hints
//  AFTER it sets client-pid, client-uid, client-type, client-path,
//  creator-pid and creator-audit-token, so a caller can override every one
//  of them. Per-app rules are therefore disabled in Serberus 0.9.0 and the
//  mechanism denies every request (AuthURIIdentityScope.perAppPinsEnabled
//  in PrivMgrCore); the lookups below stay for the release that fixes the
//  identity source.
//
//  This file is ONLY the C trampolines + dispatch table + entry point. Every
//  decision and every log line lives in Swift (SerberusAuthMechanism.swift),
//  per the "all logic lives in Swift" split in
//  docs/authuri-prompt-plugin-design.md. The ABI mirrors
//  macadmins/escrow-buddy's EBAuthPlugin.m, checked field by field against
//  Apple's AuthorizationPlugin.h; a bundle of this shape loads and receives
//  its hints on macOS 27.
//
//  Reached via hand-declared `extern` C functions (@_cdecl on the Swift side)
//  rather than the Xcode-generated -Swift.h header: under -parse-as-library
//  (which Xcode passes for every target in this repo) that header comes back
//  empty on this toolchain.
//
//  CONTRACT: every path through MechanismInvoke calls SetResult exactly once.
//  A path that returns without it hangs the client's AuthorizationCopyRights
//  indefinitely and nothing in the OS unsticks it.
//

#import <Foundation/Foundation.h>
#import <Security/AuthorizationPlugin.h>

// Swift side: SerberusAuthMechanism.swift, each @_cdecl("...")-exported.
extern void serberus_auth_plugin_did_load(void);
extern void serberus_auth_plugin_did_destroy(void);
extern void serberus_auth_mechanism_will_deactivate(void);
extern int32_t serberus_auth_decide(const char *_Nullable right,
                                     int32_t clientPID,
                                     const void *_Nullable creatorAuditToken,
                                     int32_t creatorAuditTokenLength);

#pragma mark - Hardcoded hint keys

// SPI from AuthorizationTagsPriv.h — no public header ships these. authd
// supplies all of them to a mechanism on macOS 27, but client-pid and
// creator-audit-token can be overridden by the caller's environment,
// so neither identifies anyone.
static const char *const kHintAuthorizeRight = "authorize-right";
static const char *const kHintClientPID = "client-pid";
static const char *const kHintCreatorAuditToken = "creator-audit-token";

#pragma mark - Plugin-wide state

// Exactly one AuthorizationPluginCreate per plugin host load (documented in
// AuthorizationPlugin.h and authd's engine.m), so a plain C global is correct.
static const AuthorizationCallbacks *gCallbacks = NULL;

#pragma mark - Per-mechanism-instance state

typedef struct {
    AuthorizationEngineRef engine;
} SerberusAuthInstance;

#pragma mark - Hint helpers

static NSString *_Nullable CopyHintString(AuthorizationEngineRef engine, const char *key) {
    if (gCallbacks == NULL) {
        return nil;
    }
    const AuthorizationValue *value = NULL;
    OSStatus status = gCallbacks->GetHintValue(engine, key, &value);
    if (status != errAuthorizationSuccess || value == NULL || value->data == NULL || value->length == 0) {
        return nil;
    }
    return [[NSString alloc] initWithBytes:value->data length:value->length encoding:NSUTF8StringEncoding];
}

// client-pid is a fixed-width int, not a C string — read raw and decode by
// exact width (it is 4 bytes, not 8).
static int32_t CopyHintInt32(AuthorizationEngineRef engine, const char *key) {
    if (gCallbacks == NULL) {
        return -1;
    }
    const AuthorizationValue *value = NULL;
    OSStatus status = gCallbacks->GetHintValue(engine, key, &value);
    if (status != errAuthorizationSuccess || value == NULL || value->data == NULL || value->length != sizeof(int32_t)) {
        return -1;
    }
    int32_t raw = 0;
    memcpy(&raw, value->data, sizeof(raw));
    return raw;
}

// Raw bytes of a data hint. The pointer belongs to the engine and is valid
// only for this Invoke; the Swift side copies what it needs before returning.
static const void *_Nullable CopyHintData(AuthorizationEngineRef engine, const char *key, int32_t *outLength) {
    *outLength = -1;
    if (gCallbacks == NULL) {
        return NULL;
    }
    const AuthorizationValue *value = NULL;
    OSStatus status = gCallbacks->GetHintValue(engine, key, &value);
    if (status != errAuthorizationSuccess || value == NULL || value->data == NULL) {
        return NULL;
    }
    *outLength = (int32_t)value->length;
    return value->data;
}

#pragma mark - Dispatch table entries

static OSStatus PluginDestroy(AuthorizationPluginRef inPlugin) {
    (void)inPlugin;
    serberus_auth_plugin_did_destroy();
    gCallbacks = NULL;
    return errAuthorizationSuccess;
}

static OSStatus MechanismCreate(AuthorizationPluginRef inPlugin,
                                 AuthorizationEngineRef inEngine,
                                 AuthorizationMechanismId mechanismId,
                                 AuthorizationMechanismRef *outMechanism) {
    (void)inPlugin;
    if (outMechanism == NULL) {
        return errAuthorizationInternal;
    }
    // One mechanism: "identity" (a right names it as `SerberusAuth:identity`;
    // AppIdentityBranch.mechanismName). Any other id is a rule this bundle was
    // never meant to serve — refuse to create it, which fails that evaluation
    // closed instead of running the identity check under a name nobody pinned.
    if (mechanismId == NULL || strcmp(mechanismId, "identity") != 0) {
        return errAuthorizationInternal;
    }
    SerberusAuthInstance *instance = (SerberusAuthInstance *)calloc(1, sizeof(SerberusAuthInstance));
    if (instance == NULL) {
        return errAuthorizationInternal;
    }
    instance->engine = inEngine;
    *outMechanism = (AuthorizationMechanismRef)instance;
    return errAuthorizationSuccess;
}

static OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism) {
    if (inMechanism == NULL || gCallbacks == NULL) {
        return errAuthorizationInternal;
    }
    SerberusAuthInstance *instance = (SerberusAuthInstance *)inMechanism;

    NSString *right = CopyHintString(instance->engine, kHintAuthorizeRight);
    // Passed for the log line only (and caller-claimed). While per-app
    // rules are disabled the Swift side denies without reading either hint.
    int32_t clientPID = CopyHintInt32(instance->engine, kHintClientPID);
    int32_t auditTokenLength = -1;
    const void *auditToken = CopyHintData(instance->engine, kHintCreatorAuditToken, &auditTokenLength);

    int32_t verdict = serberus_auth_decide(right.UTF8String, clientPID, auditToken, auditTokenLength);

    // Fully synchronous: no XPC, no watchdog, so this is the ONLY SetResult
    // call site and it always runs. 0 = allow; anything else denies.
    AuthorizationResult result = (verdict == 0) ? kAuthorizationResultAllow : kAuthorizationResultDeny;
    return gCallbacks->SetResult(instance->engine, result);
}

static OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism) {
    if (inMechanism == NULL || gCallbacks == NULL) {
        return errAuthorizationInternal;
    }
    SerberusAuthInstance *instance = (SerberusAuthInstance *)inMechanism;
    serberus_auth_mechanism_will_deactivate();
    // No UI, so ack immediately — the header requires DidDeactivate "as soon
    // as possible", and the instance stays alive and re-invokable.
    return gCallbacks->DidDeactivate(instance->engine);
}

static OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism) {
    if (inMechanism == NULL) {
        return errAuthorizationInternal;
    }
    free((SerberusAuthInstance *)inMechanism);
    return errAuthorizationSuccess;
}

static AuthorizationPluginInterface gPluginInterface = {
    kAuthorizationPluginInterfaceVersion,
    &PluginDestroy,
    &MechanismCreate,
    &MechanismInvoke,
    &MechanismDeactivate,
    &MechanismDestroy,
};

#pragma mark - Entry point

OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks,
                                    AuthorizationPluginRef *outPlugin,
                                    const AuthorizationPluginInterface **outPluginInterface) {
    if (callbacks == NULL || outPlugin == NULL || outPluginInterface == NULL) {
        return errAuthorizationInternal;
    }
    if (callbacks->version < kAuthorizationCallbacksVersion) {
        // Fail closed on an older-than-expected engine rather than guessing
        // at a smaller/incompatible struct layout.
        return errAuthorizationInternal;
    }
    gCallbacks = callbacks;
    serberus_auth_plugin_did_load();

    static int sentinel;
    *outPlugin = (AuthorizationPluginRef)&sentinel;
    *outPluginInterface = &gPluginInterface;
    return errAuthorizationSuccess;
}
