/*
 * authprobe-trigger.c
 *
 * Throwaway diagnostic helper for the SerberusAuthProbe spike (chunk 2 of
 * docs/authuri-prompt-plugin-design.md). Calls AuthorizationCopyRights for
 * a single right name given as argv[1] and prints the verdict.
 *
 * Why this exists instead of `security authorize <right>`: confirmed live
 * that `security authorizationdb write` unconditionally stamps a new
 * right's `identifier`/`requirement` to its OWN code identity
 * (`identifier "com.apple.security" and anchor apple`) regardless of what
 * the input plist specifies — this is not a default-when-absent behavior,
 * it overrides an explicitly-provided identifier/requirement too. A
 * satisfied `requirement` is a fast-path bypass that skips class/mechanisms
 * evaluation entirely, so triggering with `security authorize` (the same
 * binary that did the write) always self-satisfies its own stamp and
 * grants without the mechanism ever running. This binary has a different
 * code identity (ad-hoc signed, not `com.apple.security`), so it does NOT
 * satisfy that bypass — evaluation should actually reach class/mechanisms.
 *
 * Build: clang -framework Security -o authprobe-trigger authprobe-trigger.c
 * Usage: ./authprobe-trigger <right-name>
 * Exit:  0 = granted, 1 = denied/error, 2 = usage error
 */

#include <Security/Authorization.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <right-name>\n", argv[0]);
        return 2;
    }

    AuthorizationRef authRef = NULL;
    OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
                                           kAuthorizationFlagDefaults, &authRef);
    if (status != errAuthorizationSuccess) {
        fprintf(stderr, "AuthorizationCreate failed: %d\n", (int)status);
        return 1;
    }

    AuthorizationItem item;
    memset(&item, 0, sizeof(item));
    item.name = argv[1];

    AuthorizationRights rights;
    rights.count = 1;
    rights.items = &item;

    /* No kAuthorizationFlagInteractionAllowed: Stage 1/2 rights never chain
     * builtin:authenticate, so no UI should ever be needed. If this hangs
     * waiting for interaction it can't have, that's itself diagnostic
     * signal, not something to paper over by allowing interaction here. */
    status = AuthorizationCopyRights(authRef, &rights, kAuthorizationEmptyEnvironment,
                                      kAuthorizationFlagDefaults | kAuthorizationFlagExtendRights,
                                      NULL);

    printf("AuthorizationCopyRights for '%s' -> OSStatus %d (%s)\n",
           argv[1], (int)status,
           status == errAuthorizationSuccess ? "GRANTED" : "DENIED/ERROR");

    AuthorizationFree(authRef, kAuthorizationFlagDefaults);
    return status == errAuthorizationSuccess ? 0 : 1;
}
