# Changelog

## [Unreleased]

### Added
- **Maintainer avatar in the Settings → About page**: the latest GitHub profile picture of SeregonWar is fetched asynchronously at dialog open (mirroring the `UpdateChecker` async pattern, no background thread), cached in `~/.pkgtoolbox/avatar.png` and shown at 96px together with the **Donate** link (`seregonwar.com/donations`) and the project GitHub link. The cached copy appears immediately; the freshly fetched one replaces it when it arrives.
- **Installer images follow the maintainer's avatar**: the release CI refreshes `installer_assets/welcome.bmp` (portrait panel, avatar centered on a dark backdrop with a light border so dark photo edges don't blend in, plus the "SeregonWar" name below — cross-platform font with fallback) and `installer_assets/logo.bmp` (square, avatar fills it) from the avatar URL before every build, so each installer ships the current profile picture.

### Changed
- The app window icon is always the bundled **toolbox icon** (`icons/default_icon.png`), never the avatar.

### Removed
- `installer_assets/KodeKraken.ico` (old, unreferenced icon file).

## [1.5.0] - 2026-08-24

### Added
- **Redesigned Modify section** (`GUI/widgets/modify_tab.py`): a real hex editor with paginated dump (offset + 16 bytes/row + ASCII column), "Go" offset navigation and **staged edits** highlighted in red before being applied. Changes are written to a **working copy** in the temp directory — the original PKG is never touched (the old code wrote `r+b` directly on the original, with no preview or confirmation). Known header fields (Content ID / Title ID) are editable directly and staged at their file offsets; a one-time signature warning (SHA-256/NPDRM invalidation) is shown before the first write. Actions: Write to copy, Save As..., Load modified copy. Target can be the loaded PKG or a single file picked from the PKG.
- **Modify split into two sub-sections** with dedicated sidebar entries: "Hex Editor" (dump, byte staging, pending changes, write/save) and "Header Fields" (Content ID / Title ID). Switching via the sidebar or the inner tab bar keeps the sidebar highlight in sync.
- **Collapsible left PKG panel**: the PKG icon/loading column now lives in a draggable `QSplitter` (drag it to 0 to hide) and has a toolbar toggle button (columns icon, left-most) that hides/shows it. The state is persisted and restored at startup; the icon card was reduced from 320px to 180px.
- **"From PKG" buttons** in the file-analysis sections (Trophy, ESMF Decrypter, PS5 Game Info, Create TRP): pick a file directly from the loaded PKG instead of browsing the filesystem. New reusable `PkgFilePickerDialog` (searchable tree with size/type, optional extension filter, multi-select for Create TRP); the chosen file is extracted to the temp directory and loaded as if opened from disk. PS5 Game Info extracts the whole folder (eboot.bin + sce_sys/param.json).
- **NP Communication ID in the Trophy tab**: a new field with an Apply button lets you type the game's `NPWRxxxxx_00` id and re-parse an encrypted PS4 config (ESFM) on the fly — types, grades, title and hidden flags appear without leaving the tab. The working id is remembered for the session; when the config is encrypted and no id is known, the info box explains where to get it instead of silently showing "Unknown".
- **"Temi personalizzati"** section in the Settings dialog: create, save (with a name), edit and delete user themes with the full 12-color palette (borders, selection, hover, error/success/warning included) and a live preview. Themes persist in `~/.pkgtoolbox/custom_themes.json` and appear in the Appearance combo and toolbar theme menu. Replaces the old 3-color "Custom" pseudo-theme.
- **Enhanced exit confirmation**: `closeEvent` always warns when a background operation is running (extraction, pfs-info, bruteforce, file loading) or when there are unsaved edits (PS5 game info table) — regardless of the setting. The prompt gained a **"Don't ask again"** checkbox (persisted in `behavior.skip_exit_confirmation`) and explicit **Exit / Cancel** buttons (default Cancel), translated in 6 languages.
- **"Follow system theme"** option: derives its palette from the native OS (light/dark aware, re-applied on `colorSchemeChanged`).
- GitHub issue templates and a cross-platform release workflow (Windows/macOS/Linux, nightly builds).

### Changed
- Redesigned the GUI: dark-first minimal theme (default `Dark`), theme-driven styles (glassmorphism inline styles removed).
- Redesigned the sidebar: icon-first navigation grouped by sections (PKG / Strumenti / Extra), collapse toggle hides text and group labels (VS Code/Discord style).
- Rewrote the Settings dialog: left navigation list (Aspetto / Comportamento / Percorsi / Informazioni), live theme preview, Apply / OK / Cancel / Reset buttons.
- Consolidated the theme system (removed the broken `System` entry, added the real system-following option); the persisted theme is applied at startup and qt-material is no longer used.
- Sidebar now highlights the active tab and styles are re-applied on theme change.
- Fixed text contrast: removed hardcoded light backgrounds / fixed dark text from the info tree, file browser (search, tree, context menu, hex/text viewers), trophy viewers and credits label — they inherit the active theme; drag & drop states use theme colors.
- Toolbar: settings is now a **gear icon** placed **before** the theme dropdown; the theme dropdown got a **sun icon**; both recolor with the active theme.
- Window title is now translated (6 languages).
- Migrated from PyQt5 to PySide6; renamed `GraphicUserInterface` → `GUI`.
- **shadPKG now bundled on Linux and macOS too** (previously Windows-only): the release CI downloads the matching binary (`shadpkg.exe` / `shadpkg-macos` arm64 / `shadpkg-debian` x86-64) and `_find_shadpkg_exe` is platform-aware.
- Renamed the bundled-binaries folder `packages/ps3lib` → `packages/external_tools` (shadPKG, orbis-pub-cmd, runtime DLLs); all references updated.
- **Custom themes preview redesigned**: miniaturized mockup of the UI using every theme color, updating live while picking colors.
- **Release CI builds real installers on all platforms**: macOS `.dmg` (hdiutil) + zip, Linux `.AppImage` (appimagetool, FUSE-free) + tar.gz, Windows Inno Setup `.exe`.
- Fixed the release workflow: replaced the non-existent `jrsoftware/issi` action with `Minionguyjpro/Inno-Setup-Action@v1.2.2`, fixed the PyInstaller spec paths (entry script, `pathex`, data files, external tools Tree, icons — all resolved from `SPEC`; project root added to `sys.path` so `collect_all` bundles the translation JSONs), and fixed the ISS installer-asset paths (relative to `SourceDir` instead of the `.iss` folder).

### Fixed
- **Trophy extraction fixed**: `TRPReader` no longer scans for magic signatures (the `\x00\x00\x00\x00` "UCP" scan matched random data and skipped real files). It now parses the real header (big-endian, with `key_index` for version 3) and the actual entry table (name[32] + offset(8) + size(8) + flag(4) + padding[12]). Trophy images now display correctly.
- Trophy **type/grade/hidden** derived from the config XML (`ttype`, `hidden`, `title-name`, `npcommid`) instead of filename keywords; `TRPCreator` writes standard 64-byte entries (8-byte big-endian offset/size) so recompiled TRPs are readable.
- **Trophy grade recovery**: the SFM parser now tolerates a UTF-8 BOM (real Sony configs often start with one — previously every trophy showed "Unknown"); for encrypted PS4 configs it attempts best-effort decryption with the trophy key and the NP Comm IDs available from the loaded package.
- **ESMF Decrypter tab fixed**: it called a non-existent `decrypt_esmf` method; now calls `decrypt_esfm_file` and has the missing NP Comm ID input. `ESMFDecrypter` gained a reusable `decrypt_esfm_bytes` (reads the real 16-byte IV from the file, legacy zero-IV fallback, XML-validated).
- Fixed macOS crash (`NSWindow should only be instantiated on the main thread`) from worker-thread signals: slots are bound methods delivered via queued connections.
- Fixed `QThread: Destroyed while thread is still running` crash on app close: `UpdateChecker` rewritten as an async `QObject` (no background thread).
- File browser context menu unreadable (menu had no parent, missed the theme stylesheet) and preview too small (splitter now 1:2 in favor of the preview).

### Removed
- **Inject tab** (placeholder WIP): per PSDevWiki research, in-place file injection into retail PS4/PS5 PKGs is not viable — entries are encrypted and every digest plus the NPDRM signature would be invalidated. README/roadmap updated (future "PKG Rebuild" approach).
- Dead code cleanup: deleted unused modules (`GlobalUsing.py`, `ListViewDraw.py`, `DialogHelper.py`, `system.py`, `Trophy.py`/`TrophyFile`, `Trophy/Utilities.py`, `packages/utils.py`, `packages/PackagePS4.py`, `packages/edat.py`, `packages/key.py`, `tools/repack.py`, `tools/IllegalNameCheck.py`, `tools/file_viewer_dialog.py`, `GUI/widgets/custom_tree.py`, `GUI/widgets/dump_tab.py`, the `Utilities/Constants` package, the `file_operations` package, dead CLI code in `main.py`), dead code (`AES_cbc_encrypt`, `get_ps5_game_info`, `Bitmap`/`Trophy` classes, `bcolors`/`print_aligned`, unused enums) and dozens of unused imports.
