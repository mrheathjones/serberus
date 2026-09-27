# Serberus documentation

Start with the [project README](../README.md) for what Serberus is and how to
build it, and [SECURITY.md](../SECURITY.md) for its security model and how to
deploy it safely.

## How it works

- [SERBERUS-OVERVIEW.md](SERBERUS-OVERVIEW.md): the whole system, including
  components, enforcement modes, daemon states, configuration, install flow,
  and a Jamf Pro deployment checklist.
- [footprint.md](footprint.md): what Serberus changes on a Mac, what talks to
  the network, what each uninstaller removes, and how to verify the installed
  binaries.
- [SerberusPAM.md](SerberusPAM.md): the `pam_serberus` module that gates `sudo`.
- [sudoers-provisioning.md](sudoers-provisioning.md): the coarse
  `/etc/sudoers.d/serberus` drop-in that lets standard users reach `sudo`, and
  how users are enrolled in it.
- [authuri-identity-scoped-rules.md](authuri-identity-scoped-rules.md): the
  SerberusAuth authorization plugin, and the rules that give specific apps
  their own posture on an authorization right. Those rules are disabled in
  0.9.0 because the app's identity can be forged; the document starts
  with what that means for existing profiles.

## Writing and delivering policy

- [policy-authoring-symlinked-binaries.md](policy-authoring-symlinked-binaries.md):
  writing `sudo` rules that match and constrain commands installed behind a
  symlink or that dispatch subcommands, such as `jamf`.
- [jamf-profile-delivery.md](jamf-profile-delivery.md): getting configuration
  and rule profiles into Jamf Pro, and the seven preference domains. The config
  domain has a second schema,
  `com.herojoneslabs.serberus.config.enrollment.json`, for delivering
  `sudoEnrollment` as its own profile. Only one profile may set
  `sudoEnrollment`.
- [Support/sample-profiles/README.md](../Support/sample-profiles/README.md):
  which sample profile is for what (mode, test or production layout, `.plist`
  or `.mobileconfig`), and what to replace before you deploy one.
- [`Support/jamf-schemas/`](../Support/jamf-schemas/): Jamf custom schemas for
  each preference domain.
- [Support/jamf-extension-attributes/README.md](../Support/jamf-extension-attributes/README.md):
  Jamf extension attributes that report Serberus's state, mode and activity.

## Design records

- [authuri-prompt-plugin-design.md](authuri-prompt-plugin-design.md): the
  design for a Serberus approval prompt on authorization rights. It isn't
  built; the shipped plugin, inert in 0.9.0, is described in
  [authuri-identity-scoped-rules.md](authuri-identity-scoped-rules.md).

## Building and shipping

- [PKG/README.md](../PKG/README.md): which installer package to build, signing,
  and install order.
- [esf-provisioning-and-notarization.md](esf-provisioning-and-notarization.md):
  getting the optional Endpoint Security entitlement for the exec gate, and
  notarizing a production build.
- [CONTRIBUTING.md](../CONTRIBUTING.md): setting your team, running the tests,
  and submitting changes.
