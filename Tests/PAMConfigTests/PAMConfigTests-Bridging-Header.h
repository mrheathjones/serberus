/*
 * Bridging header for the PAMConfigTests bundle: exposes the PAM module's
 * pure C config reader (pam_config.c) to Swift Testing. pam_config.h is
 * resolved via HEADER_SEARCH_PATHS (Sources/pam_serberus) configured on the
 * PAMConfigTests target in project.yml.
 */

#import "pam_config.h"
#import "pam_decisions.h"
#import "sudo_args.h"
