# Package core architecture

PkgToolBox opens desktop sources through `packages.factory.open_source`.
Binary package detection remains centralized in `open_package`, so a root
`CNT` can be distinguished as PS4 or PS5 meta from its validated entry/name
table instead of unreliable file-tail heuristics. GP4/GP5 XML projects and
standalone files are routed to separate read-only workspace adapters.

## Layers

- `binary.py`: checked random-access reads and range arithmetic.
- `exceptions.py`: stable format, bounds, encryption, and capability errors.
- `sfo.py`: complete PARAM.SFO parser and JSON-ready document model.
- `metadata.py`: readable PS4 content/DRM/flag names and region inference.
- `image_info.py`: header-only PNG/DDS inspection and asset classification.
- `pfs.py`: PS4 PFS geometry plus plaintext PFSC header/sector-map validation.
- `package_base.py`: safe reads, image enumeration, and atomic streaming extraction.
- `package_ps4.py` / `package_ps5.py`: platform container parsers.
- `gp5_project.py`: GP5 flat/rootdir parsing, path mapping, validation, previews,
  and atomic project export.
- `gp4_project.py`: GP4 `targ_path`/`orig_path` mappings plus PARAM.SFO metadata.
- `file_source.py`: the single-file workspace used for arbitrary local files.

## Desktop workspace

The GUI presents four stable workspaces instead of a peer-level page for every
tool:

- Overview: source identity, readiness, warnings, and next actions.
- Contents: mapped files, images, and PFS inspection.
- Inspect & edit: hex inspection, staged writes, and supported header fields.
- Tools: trophies, ESMF, TRP creation, PS5 executable info, and encryption.

Package images, GP4/GP5 projects, and individual files use the same contents
browser. Capabilities remain source-specific: publishing projects expose their
source mappings and manifest metadata but do not claim to contain a PFS or an
installable package image.

## Publishing projects

Both commonly encountered layouts are supported:

- flat `<files>` / `<folders>` mappings, including the leading-backslash
  project-relative paths emitted by gengp5;
- recursive `<rootdir>` projects with global, directory, and file exclusions.

`sce_sys/param.json` is read when present to recover title and content
metadata. Missing mappings remain visible as warnings. DTD and entity
declarations, unsafe destination traversal, and duplicate destinations are
rejected or reported rather than silently followed.

GP4 projects use the explicit `<files>` mapping (`targ_path` / `orig_path`)
emitted by gengp4. `sce_sys/param.sfo` is parsed when available. Both formats
mask passcode values in the UI and remain read-only.

## Extraction policy

All offsets and sizes are validated before I/O. Entry paths must remain inside
the selected output directory. Files are streamed into a temporary file and
atomically moved into place only after a complete read. An entry with the
encryption flag set is never returned as plaintext and is reported as skipped.

PS5 supplementary `SI` ZIP members use the same traversal checks and streaming
policy. Encrypted ZIP members and malformed archives are not extracted.

## Capability boundary

The internal engine can parse and extract clear-text PS4 metadata, inspect PFS
container/PFSC geometry, parse PS5 FIH/CNT/meta packages, and extract clear-text
CNT and SI files. A protected PS4 PFS normally needs RSA key unwrap, HMAC key
derivation, AES-XTS sector decryption, PFSC decompression, and inode traversal.
Until that full pipeline has verified fixtures, the UI reports
`protected-or-unsupported`; it does not run a guessed AES transform or claim a
passcode succeeded.
