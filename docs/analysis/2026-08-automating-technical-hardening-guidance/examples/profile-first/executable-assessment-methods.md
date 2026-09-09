# Executable Assessment Methods: Automation Scripts on Controls in Catalogs and Profiles

*Concept note, September 2026.*

SP 800-53A has always known three ways to assess a control: EXAMINE, INTERVIEW, TEST. When NIST published 800-53 in OSCAL, those methods went into the catalog as `assessment-method` parts on every control, next to the assessment objectives. The catalog states the requirement and, in the same document, how to check it. What the TEST method lacks is a body. It says "test the mechanism", and a human decides what that means for the system in front of them.

This note proposes to give TEST a body: an executable assessment method, attached to a control as an OSCAL part, in the catalog when the author of the requirement supplies the check and in a profile when someone else supplies it for a specific platform. The mechanism is not tied to CIS, to benchmarks or to bash. It works for a Grundschutz-Baustein with a kubectl check, for 800-53 SI-2 with an apt check, for an ISO 27001 mapping with a KQL query against Sentinel, and for a CIS Benchmark rule with the SCE script CIS already ships. The script language, the execution engine and the evaluation rule are properties of the part; OSCAL provides the envelope and the identity.

## What is wrong with the alternatives

The recent hardening-guidance discussion weighed three homes for automated checks: the catalog or profile, the component definition, and the assessment plan. The component-definition route, which our own earlier draft took, attaches scripts to `implemented-requirement` elements. It works for a single vendor shipping a single file, and it ends there. An implemented requirement has no id a profile can alter, no objective a finding can target, no parameter a tailoring party can set. The custom `automation-script` assembly the draft introduced had to reinvent all three (`benchmark-rule-id`, `applicable-profiles`, an SSP switch), and every consumer has to learn a schema fork to read it.

The assessment-plan route puts scripts where the assessment happens. That is correct for a one-off check an assessor writes for one system. For a check that belongs to the requirement, it means copying the script into every assessment plan for every system, with no upstream to pull updates from.

The check belongs to the control. The control has an id, parts, params and links, and the profile and assessment layers already operate on all four.

## The mechanism

An executable assessment method is an `assessment-method` part with `method=TEST`, a set of namespaced props that describe how to run and evaluate it, and a body: either a fenced code block in `prose` or a link to a back-matter resource. NIST 800-53 SI-2 (Flaw Remediation), tailored for Ubuntu in a profile:

```json
{
  "control-id": "si-2",
  "adds": [
    {
      "position": "ending",
      "parts": [
        {
          "id": "si-2_obj-ubuntu-updates",
          "name": "assessment-objective",
          "prose": "Unattended security upgrades are enabled and no security update is pending."
        },
        {
          "id": "si-2_asm-ubuntu-updates",
          "name": "assessment-method",
          "props": [
            { "name": "method", "value": "TEST" },
            { "name": "platform", "value": "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*", "ns": "https://example.org/ns/oscal-automation" },
            { "name": "language", "value": "bash", "ns": "https://example.org/ns/oscal-automation" },
            { "name": "evaluation", "value": "exit-code", "ns": "https://example.org/ns/oscal-automation" },
            { "name": "pass-condition", "value": "0", "ns": "https://example.org/ns/oscal-automation" },
            { "name": "timeout", "value": "PT60S", "ns": "https://example.org/ns/oscal-automation" }
          ],
          "links": [
            { "rel": "assessment-objective", "href": "#si-2_obj-ubuntu-updates" }
          ],
          "prose": "```bash\nsystemctl is-enabled unattended-upgrades >/dev/null &&\ntest \"$(apt list --upgradable 2>/dev/null | grep -c -- '-security')\" -eq 0\n```"
        }
      ]
    }
  ]
}
```

The namespace is a placeholder; the vocabulary is the point. Five props carry everything an executor needs: which platform the check applies to (a CPE, matched against the component in the SSP, the same way XCCDF matches its `platform` element), which engine runs it, how the result is evaluated, what counts as pass, and how long to wait. The evaluation prop is an enumeration: `exit-code`, `stdout-regex`, `json-path`, `oval-result`, `inspec-profile`. Each value fixes the meaning of `pass-condition`. Metaschema external constraints enforce the enumeration on standard OSCAL, the way FedRAMP enforces its vocabulary without forking the model.

Three further pieces of the standard model do work the custom assembly had to fake.

The control's `params` feed the script. A Grundschutz requirement with a parameter for the maximum password age, a CIS rule with the kernel module name, an organizational policy with the list of approved ciphers: the profile sets the value with `set-parameter`, and the executor exports it to the script as an environment variable named after the param id. One script, many controls, many organizations. CIS ships 71 distinct SCE scripts for 129 of the 279 Ubuntu 22.04 rules; `nix_auditd_rule_chk.sh` alone serves 47 rules, each with its own exported value. That is the pattern, and OSCAL params are its native form.

Back-matter resources hold the script bodies that are reused or too large for inline prose. An `rlink` with `media-type` and a SHA-256 hash, or `base64` for self-contained catalogs. The part links to the resource by uuid. One resource, 47 links.

The `assessment-objective` part gives the check its identity in the results. Findings in the assessment-results model target an `objective-id`. A scripted method that links to its objective produces findings that every AR consumer built for 800-53A displays unchanged.

## Catalog or profile

Both, by who owns the check.

The check goes into the catalog when the author of the requirement is also the author of the check and the requirement is already technology-specific. CIS Benchmarks are the obvious case: the recommendation and the SCE script are published by the same organization for the same platform, and separating them serves nobody. A Kubernetes-specific Baustein could ship its own checks the same way.

The check goes into a profile when the catalog is technology-neutral or when someone other than the catalog author supplies it. 800-53 will never carry an apt command, and it should not. The organization that runs 800-53 moderate on Ubuntu writes a profile that imports the baseline and adds the checks. A tool vendor publishes "Grundschutz-Kompendium, SYS.1.6 with executable checks for Kubernetes", a profile that imports the BSI catalog untouched and adds a part to SYS.1.6.A17, the requirement that containers run without privileges, containing a kubectl query for `securityContext.privileged` across all namespaces. A second vendor ships the same for OpenShift, a third replaces bash with Ansible or OPA. The BSI catalog remains the BSI artifact.

This division works only because the check is a part. A profile can add parts, props, links and params to a control; it cannot add an assembly the model does not know. Any design that models the check as a custom assembly is unalterable by profiles, and profiles are where most checks will be written.

## The executor

The tooling side is a resolver with six steps. a) Resolve the profile the SSP imports, and for each component, the profile the component references, if any. b) For each control and each component, select the `assessment-method` parts with `method=TEST` whose `platform` matches the component. c) Bind the control's params from the resolved profile to environment variables. d) Fetch the body from prose or back-matter, verify the hash, execute with the engine named in `language`, enforce the timeout. e) Apply the evaluation rule to the result. f) Write an observation with the raw output as `relevant-evidence` and a finding targeting the objective id.

Nothing in the SSP changes. The 304-to-867 growth that discredited "benchmark as catalog" in the hardening discussion came from importing benchmark profiles into the SSP's own profile. Executable methods on controls do not touch the SSP's control set. They are read by the assessment plan, not by the system owner.

## Security of executable catalogs

A catalog with executable assessment methods is code. An organization that resolves a profile from a URL and runs what it finds has installed a remote code execution path into every assessed system, with the profile author as the operator. Pin the hash of every rlink, sign the catalog and the profile, and let the executor refuse anything unverified. Run checks read-only wherever the engine allows it; a remediation script is a different part with a different name (`remediation`, namespaced) and a different approval. Do not let the convenience of a self-updating check library become the reason an auditor's laptop can reconfigure production.

## What it does not solve

The mechanism does not standardize the scripts. Bash, PowerShell, InSpec, OPA, OVAL and KQL stay what they are; OSCAL wraps them. Two vendors can ship two incompatible checks for the same control, and the profile author picks. That is the same situation XCCDF has been in since 2005 with `check-content-ref`, and it has not stopped scanners from being built on it.

Version coupling is real. A changed check is a new profile version, and a changed catalog check is a new catalog version. For catalogs that ship checks (benchmarks), that coupling already exists in the source material. For profiles, it is the same coupling any tailoring has.

The `platform` prop as CPE is a convention until someone writes it down; CPE has its own maintenance problems and a plain token may serve as well. The evaluation vocabulary needs an owner. Both are conventions, not model gaps.

## Recommendation

Attach executable checks to controls as `assessment-method` parts with `method=TEST`, in the catalog when the requirement author owns the check and in a profile otherwise. Carry platform, engine, evaluation rule and pass condition as namespaced props, validated by external constraints. Feed scripts from control params, store shared bodies in back-matter with hashes, and link every method to an assessment objective so findings need no new field. Do not put checks into implemented requirements or assessment plans; nothing there can be tailored, mapped or targeted. The check is a property of the requirement. Model it where the requirement lives.
