//
//  SerberusAuthProbeShim.m
//  SerberusAuthProbe
//
//  Throwaway spike plugin — chunk 2 of the implementation plan in
//  docs/authuri-prompt-plugin-design.md. Its only job is answering that doc's open questions
//  (does an Apple-Development-signed bundle load into SecurityAgentHelper on
//  this macOS ring; does evaluate-mechanisms drive on a System Settings
//  right; what hints actually arrive; how SetResult(deny) and
//  kAuthorizationResultUndefined behave; etc.) on a single scratch/test Mac.
//  extras/SerberusAuthProbe/authprobe-spike.sh wires it up and reads the results.
//
//  This is NOT the production SerberusAuth.bundle: no daemon, no XPC, no
//  fail-closed guarantee beyond "unrecognized mechanismId -> undefined".
//  Never reference it from a right the daemon manages.
//
//  ABI mirrors macadmins/escrow-buddy's EBAuthPlugin.m (the proven pattern
//  cited in docs/authuri-prompt-plugin-design.md) — dispatch table field order/types verified
//  verbatim against Apple's AuthorizationPlugin.h. Unlike Escrow Buddy, this
//  file is ONLY the C trampolines + dispatch table + entry point; every
//  decision and every log line lives in Swift
//  (SerberusAuthProbeMechanism.swift), the "all logic lives in Swift" split
//  docs/authuri-prompt-plugin-design.md describes.
//
//  Reached via hand-declared `extern` C functions (@_cdecl on the Swift
//  side), NOT the Xcode-generated SerberusAuthProbe-Swift.h: on this
//  toolchain, `-parse-as-library` (which Xcode always passes for a
//  non-main.swift library-shaped target — every target in this repo) makes
//  the generated header come back completely empty, confirmed with a
//  minimal repro. @_cdecl is a narrower, longstanding FFI mechanism that
//  isn't affected by that.
//

#import <Foundation/Foundation.h>
#import <Security/AuthorizationPlugin.h>

// Swift side: SerberusAuthProbeMechanism.swift, each @_cdecl("...")-exported.
extern void serberus_probe_plugin_did_load(void);
extern void serberus_probe_plugin_did_destroy(void);
extern void serberus_probe_mechanism_created(const char *_Nullable mechanismId);
extern void serberus_probe_mechanism_destroyed(const char *_Nullable mechanismId);
extern void serberus_probe_mechanism_will_deactivate(const char *_Nullable mechanismId);
extern int32_t serberus_probe_decide(const char *_Nullable mechanismId,
                                      const char *_Nullable right,
                                      int32_t clientUID,
                                      int32_t clientPID,
                                      const char *_Nullable clientPath,
                                      const void *_Nullable creatorAuditToken,
                                      int32_t creatorAuditTokenLength);

#pragma mark - Hardcoded hint keys

// SPI from AuthorizationTagsPriv.h — no public header ships these, so they
// are hardcoded string literals (docs/authuri-prompt-plugin-design.md):
// stable 10+ years, no Apple contract.
static const char *const kHintAuthorizeRight = "authorize-right";
static const char *const kHintClientUID = "client-uid";
static const char *const kHintClientPID = "client-pid";
static const char *const kHintClientPath = "client-path";
static const char *const kHintCreatorAuditToken = "creator-audit-token";

#pragma mark - Plugin-wide state

// Set once by AuthorizationPluginCreate. The header and engine.m both
// document exactly one AuthorizationPluginCreate call per plugin host load,
// so a plain C global (rather than something threaded through every call)
// is correct here.
static const AuthorizationCallbacks *gCallbacks = NULL;

#pragma mark - Per-mechanism-instance state

// AuthorizationMechanismRef is an opaque void*. mechanismId is a strdup'd C
// string, freed in MechanismDestroy.
typedef struct {
    AuthorizationEngineRef engine;
    char *mechanismId;
} SerberusProbeInstance;

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

// client-uid/client-pid are fixed-width ints, not C strings — read raw and
// decode by exact width (docs/authuri-prompt-plugin-design.md: "client-pid
// is 4 bytes, not 8").
// outFound distinguishes "hint absent" from "hint present with value 0".
static int32_t CopyHintInt32(AuthorizationEngineRef engine, const char *key, BOOL *outFound) {
    *outFound = NO;
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
    *outFound = YES;
    return raw;
}

// Raw bytes of a data hint. The pointer belongs to the engine and is only
// valid for this Invoke, which is fine: the Swift side copies what it needs
// before returning. Length -1 means the hint was absent.
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
    serberus_probe_plugin_did_destroy();
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

    serberus_probe_mechanism_created(mechanismId);

    SerberusProbeInstance *instance = (SerberusProbeInstance *)calloc(1, sizeof(SerberusProbeInstance));
    if (instance == NULL) {
        return errAuthorizationInternal;
    }
    instance->engine = inEngine;
    instance->mechanismId = (mechanismId != NULL) ? strdup(mechanismId) : NULL;

    *outMechanism = (AuthorizationMechanismRef)instance;
    return errAuthorizationSuccess;
}

static OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism) {
    if (inMechanism == NULL || gCallbacks == NULL) {
        return errAuthorizationInternal;
    }
    SerberusProbeInstance *instance = (SerberusProbeInstance *)inMechanism;

    NSString *right = CopyHintString(instance->engine, kHintAuthorizeRight);
    BOOL foundUID = NO;
    BOOL foundPID = NO;
    int32_t clientUID = CopyHintInt32(instance->engine, kHintClientUID, &foundUID);
    int32_t clientPID = CopyHintInt32(instance->engine, kHintClientPID, &foundPID);
    NSString *clientPath = CopyHintString(instance->engine, kHintClientPath);
    int32_t auditTokenLength = -1;
    const void *auditToken = CopyHintData(instance->engine, kHintCreatorAuditToken, &auditTokenLength);

    int32_t verdictRaw = serberus_probe_decide(instance->mechanismId,
                                                right.UTF8String,
                                                (foundUID ? clientUID : -1),
                                                (foundPID ? clientPID : -1),
                                                clientPath.UTF8String,
                                                auditToken,
                                                auditTokenLength);

    AuthorizationResult result;
    switch (verdictRaw) {
        case 0: result = kAuthorizationResultAllow; break;
        case 1: result = kAuthorizationResultDeny; break;
        default: result = kAuthorizationResultUndefined; break;
    }
    // Every code path through MechanismInvoke must call SetResult exactly
    // once (docs/authuri-prompt-plugin-design.md). This spike is fully synchronous — no
    // async XPC, no watchdog — so this is the ONLY call site, and it always
    // runs.
    return gCallbacks->SetResult(instance->engine, result);
}

static OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism) {
    if (inMechanism == NULL || gCallbacks == NULL) {
        return errAuthorizationInternal;
    }
    SerberusProbeInstance *instance = (SerberusProbeInstance *)inMechanism;
    serberus_probe_mechanism_will_deactivate(instance->mechanismId);
    // No UI in this mechanism, so DidDeactivate immediately — mirrors
    // EBAuthPlugin.m's own comment on the identical case.
    return gCallbacks->DidDeactivate(instance->engine);
}

static OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism) {
    if (inMechanism == NULL) {
        return errAuthorizationInternal;
    }
    SerberusProbeInstance *instance = (SerberusProbeInstance *)inMechanism;
    serberus_probe_mechanism_destroyed(instance->mechanismId);
    free(instance->mechanismId);
    free(instance);
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
    serberus_probe_plugin_did_load();

    // No real per-plugin state beyond gCallbacks (a plain C global), so hand
    // back a non-NULL sentinel rather than allocating something unused.
    static int sentinel;
    *outPlugin = (AuthorizationPluginRef)&sentinel;
    *outPluginInterface = &gPluginInterface;
    return errAuthorizationSuccess;
}
