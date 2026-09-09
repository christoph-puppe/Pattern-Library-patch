# Executable-first: the concept note, and a corpus generated in its shape

No proponent has published OSCAL for the executable-first approach. What its
proponent has published is the concept note in this directory,
`executable-assessment-methods.md`. Everything under `oscal/` was written by
`tools/executable_first_corpus.py`, from two pieces of published hardening
guidance this repository already holds, in the shape the note proposes. The
files are the site's, and the site says so wherever it counts them.

## What is here

| File | Model | From |
|---|---|---|
| `cis-ubuntu-24-04-lts-benchmark-catalog.json` | catalog | `sources/cis/CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v1.0.0.json` |
| `cis-ubuntu-24-04-lts-level-1-server-profile.json`, and the three beside it | profile | the benchmark's own four profiles |
| `cis-ubuntu-24-04-lts-to-nist-sp-800-53-rev5-mapping.json` | mapping-collection | the SP 800-53 references in the benchmark's own identifiers |
| `nist-sp-800-53-rev5-with-ubuntu-24-04-lts-stig-profile.json` | profile | `sources/disa/U_CAN_Ubuntu_24-04_LTS_STIG_V1R5_Manual-xccdf.xml`, and the CCI to control mapping in the STIG's published OSCAL conversion |
| `cis-ubuntu-24-04-lts-benchmark-automation-scripts-component-definition.json` | component-definition, Rules shape | the same benchmark file, as a validation component carrying an `automation-scripts` assembly |

Two routes, because the note names two, and then the same benchmark once more
in the other construct.

**The Rules shape**, for the second construct the site compares. The benchmark
becomes a validation component whose implemented requirements are keyed to the
CIS Controls v8 safeguards the benchmark names in its own identifiers, and
each carries an
`automation-scripts` object per audit or remediation script: type, language,
the benchmark profiles it applies to, evaluation criteria where the script
prints the result line, and the script as payload. Recommendations that name
no CIS Control sit under a second control implementation whose source is the
catalog beside the file. OSCAL 1.2.1 does not define `automation-scripts`, so
this file fails validation, the generator expects it to, and `--conformance`
checks that it does. A recommendation naming two safeguards is carried under
both, because the shape has no link between two requirements' scripts.

**The catalog route**, where the author of the requirement is the author of the
check. Every CIS recommendation is a control carrying an `assessment-objective`
part, an `assessment-method` part with `method` TEST or EXAMINE as the benchmark
says, the audit procedure as its body, and a `remediation` part. The method
carries the note's props: `platform`, the CPE the benchmark publishes;
`language` bash where the audit is a bash script or a Script Check Engine
script is named; and `evaluation` and `pass-condition` where the script prints
the audit result line CIS's scripts print. Each SCE script the benchmark's
check expression names is a back-matter resource the method links to, and the
value CIS-CAT exports to it is a parameter of the control. The benchmark's four
profiles are four OSCAL profiles, and its own SP 800-53 references are a mapping
collection.

**The profile route**, where someone other than the catalog author supplies the
check. The STIG becomes a profile that imports the NIST Revision 5 catalog and
adds, to each control a rule's CCIs map to, an objective carrying the rule and
a method carrying DISA's check text. A rule that serves more than one control
puts its parts on the first and links the others to the objective.

## What is real and what is derived

Every control, part, identifier, value and script body is taken from the
source file. The shape is the generator's. Three things are worth knowing
before reading the files as if a publisher had shipped them.

- CIS's audit prose is XHTML in the benchmark file and OSCAL prose is Markdown,
  so it is converted: paragraphs, lists, emphasis, inline code and fenced
  blocks. Nothing is reworded.
- One benchmark section holds recommendations and a sub-section together,
  which an OSCAL group cannot. Its own recommendations sit in a sub-group whose
  id ends in `_recommendations`. That is the one place the structure is not
  CIS's.
- The STIG carries no CPE, so its methods take the platform CIS publishes for
  the same operating system.

## What is not here

- The SCE script bodies ship with CIS-CAT and are not in the benchmark file.
  Their resources carry a name and no hash, which is exactly the gap the note's
  security section says an executor must refuse.
- DISA publishes the STIG's checks as text a person follows. The SCAP content
  that automates them ships separately and is not held, so the STIG's methods
  name no engine and no evaluation rule.
- No system security plan, assessment plan or assessment result. Nothing has
  been run.

## Checking it

```
python tools/executable_first_corpus.py --check      the committed files are what the generator writes
python tools/executable_first_corpus.py --validate   every file against OSCAL 1.2.1, if trestle is on the path
python tools/verify.py --corpus                   the counts, the links and the structure, recomputed
```

The seven assessment-method files validate under compliance-trestle 5.1.0,
which carries the OSCAL 1.2.1 schemas, and under the published JSON schemas
for the catalog, profile and mapping models. The Rules-shape file fails, on
the `automation-scripts` field, and that is the expected result.
