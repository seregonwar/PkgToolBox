# Changelog

## [Unreleased]

### Fixed
- **Trophy extraction fixed**: `TRPReader` no longer scans for magic signatures (the `\x00\x00\x00\x00` "UCP" scan matched random data and skipped real files). It now parses the real header (big-endian, with `key_index` for version 3) and the actual entry table (name[32] + offset(8) + size(8) + flag(4) + padding[12], size from the header's `entry_size` field). Trophy images now display correctly in the Trophy tab.
- Trophy **type/grade/hidden** are now derived from the unencrypted `.SFM` config XML (`ttype`, `hidden`, `title-name`, `npcommid`) instead of filename keywords that real TRP files never contain; encrypted entries are flagged. `TRPCreator` now writes standard 64-byte entries (8-byte big-endian offset/size), so recompiled TRPs are readable.

### Added
- **Redesigned Modify section** (`GUI/widgets/modify_tab.py`): a real hex editor with paginated dump (offset + 16 bytes/row + ASCII column), "Go" offset navigation, and **staged edits** highlighted in red in the dump before being applied. Changes are written to a **working copy** in the temp directory — the original PKG is never touched (old code wrote `r+b` directly on the original with no preview or confirmation). Known header fields (Content ID / Title ID) are editable directly and staged at their file offsets; a signature warning (SHA-256/NPDRM invalidation) is shown once before the first write. Actions: Write to copy, Save As..., Load modified copy (reloads the modified PKG). Target can be the loaded PKG or a single file picked from the PKG ("From PKG").
- **"From PKG" buttons** in the file-analysis sections (Trophy, ESMF Decrypter, PS5 Game Info, Create TRP): pick a file directly from the loaded PKG instead of browsing the filesystem. A new reusable `PkgFilePickerDialog` lists the PKG contents (searchable tree with size/type, optional extension filter, multi-select for Create TRP); the chosen file is extracted to the temp directory and loaded as if it were opened from disk. For PS5 Game Info the whole folder (eboot.bin + sce_sys/param.json) is extracted, since the tool needs the surrounding directory.

### Fixed
- **File browser context menu unreadable**: the right-click menu was created without a parent (`QMenu()`), so the app-wide theme stylesheet never reached it and the items lost all contrast. It is now parented to the browser and gets the active theme colors explicitly (background/text/selection) — readable in every theme.
- **File browser preview too small**: the splitter now gives the preview panel (hex/text view) more room than the file tree (stretch 1:2 instead of 2:1, initial sizes 360/560).

### Changed
- **shadPKG now bundled on Linux and macOS too** (previously Windows-only): the release CI downloads the matching binary from the ShadPKG releases (v2.1.0: `shadpkg.exe` / `shadpkg-macos` arm64 / `shadpkg-debian` x86-64) into `packages/external_tools/` before building, and `_find_shadpkg_exe` looks for `shadPKG.exe` on Windows and `shadPKG` on Unix. README documents the manual step for local dev.
- Renamed the bundled-binaries folder `packages/ps3lib` → `packages/external_tools` (it holds shadPKG, orbis-pub-cmd and runtime DLLs, not just PS3 tools); all references updated (spec, CI, code, README, .gitignore).
- **Custom themes preview redesigned**: the editor now shows a miniaturized mockup of the UI that uses every theme color (window background/border, sidebar with selected item, title/secondary text, input, accent button, success/warning/error badges) and updates live while picking colors.
- **Release CI now builds real installers on all platforms**: macOS gets a `.dmg` (via `hdiutil`) in addition to the zip, Linux gets an `.AppImage` (via appimagetool, FUSE-free) in addition to the tarball — Windows already built an Inno Setup `.exe`.
- Toolbar icons: the settings button is now a **gear icon** (was a generic list icon) and is placed **before** the theme dropdown; the theme dropdown got a **sun icon** next to its label. Both recolor with the active theme.
- Migrated from PyQt5 to PySide6 with qt-material Material Design theming.
- Renamed the `GraphicUserInterface` package to `GUI`.
- Removed the unused `file_operations` package and the dead CLI code in `main.py`.
- Added GitHub issue templates and a cross-platform release workflow (Windows/macOS/Linux, nightly builds).

### Changed
- Fixed text contrast issues: removed hardcoded light backgrounds (`white`, `#f8f9fa`) from the info tree, file browser (search, tree, context menu, hex/text viewers), trophy info/hex viewers, and the fixed dark text color from the credits label — those widgets now inherit their colors from the active theme. The drag & drop zone states (hover/leave/drop) now use theme colors instead of fixed gradients.
- Added a dedicated **"Temi personalizzati"** section in the Settings dialog: create, save (with a name), edit and delete user-defined themes with the full color palette (12 colors incl. borders, selection, hover, error/success/warning) and a live preview. Themes persist in `~/.pkgtoolbox/custom_themes.json` and appear automatically in the Appearance combo and the toolbar theme menu. Replaced the old 3-color "Custom" pseudo-theme.
- Fixed the window title not being translated: added the `PKG Tool Box v1.4.0` key to all locale files (now shows e.g. `PkgToolBox v1.4.0` in Italian, `PKGツールボックス v1.4.0` in Japanese).
- Enhanced the exit confirmation: `closeEvent` now always warns when a **background operation is running** (extraction, pfs-info, bruteforce, file loading) or when there are **unsaved edits** (PS5 game info table) — regardless of the setting. The plain prompt gained a **"Don't ask again"** checkbox (persisted in `behavior.skip_exit_confirmation`) and explicit **Exit / Cancel** buttons (DestructiveRole/RejectRole, default Cancel), all translated in 6 languages.
- Sidebar now highlights the active tab: nav buttons are checkable (auto-exclusive) and stay in sync via `tab_widget.currentChanged`, so the highlight follows any tab switch (sidebar click, menu, shortcuts, drag & drop).
- Consolidated the theme system: removed the broken `System` combo entry; added a real **"Follow system theme"** option that derives its palette from the OS (light/dark aware, re-applied on `colorSchemeChanged`).
- The persisted theme is now applied at startup (previously `main.py` always forced qt-material `light_blue.xml`); qt-material is no longer used.
- Sidebar styles are now re-applied on theme change (previously only the icons were recolored).
- Redesigned the GUI: dark-first minimal theme (default `Dark`), removed the glassmorphism inline styles, replaced them with theme-driven styles.
- Redesigned the sidebar: icon-first navigation grouped by sections (PKG / Strumenti / Extra), collapse toggle now hides text and group labels (VS Code/Discord style).
- Rewrote the Settings dialog: left navigation list (Aspetto / Comportamento / Percorsi / Informazioni), live theme preview, Apply / OK / Cancel / Reset buttons.
- Removed the dead `Utilities/Settings` package (old Settings.conf system) and the unused `GUI/utils/settings_manager.py`.

### Fixed
- Fixed macOS crash (`NSWindow should only be instantiated on the main thread`) caused by worker-thread signals connected to plain Python closures: `QMessageBox` and widget updates were running in the worker thread. Slots are now bound methods, delivered to the main thread via queued connections (`pfs_info_tab.py`, `main_window.py` `run_pfs_info`/`extract_pkg`, `file_browser.py`).
- Fixed `QThread: Destroyed while thread is still running` crash on app close: `UpdateChecker` rewritten as an async `QObject` using `QNetworkAccessManager` (no background thread).

### Removed
- Removed the Inject tab (placeholder WIP). Per PSDevWiki research, in-place file injection into retail PS4/PS5 PKGs is not viable: entries are encrypted (flags/key index) and every entry/body/content digest plus the NPDRM signature would be invalidated. README and roadmap updated accordingly (future "PKG Rebuild" approach).

### Removed (dead code cleanup)
- Deleted unused modules: `GlobalUsing.py`, `ListViewDraw.py`, `DialogHelper.py`, `system.py`, `Trophy.py`/`TrophyFile`, `Trophy/Utilities.py`, `packages/utils.py` (duplicate of `pkgtoolbox/core/utils.py`), `packages/PackagePS4.py`, `packages/edat.py`, `packages/key.py`, `tools/repack.py`, `tools/IllegalNameCheck.py`, `tools/file_viewer_dialog.py`, `GUI/widgets/custom_tree.py`, `GUI/widgets/dump_tab.py` and the whole `Utilities/Constants` package.
- Removed dead code: `AES_cbc_encrypt`, `get_ps5_game_info`, `Bitmap`/`Trophy` classes in `Helper.py`, `bcolors`/`print_aligned`, unused enums `Type`/`PackageType`/`PackageFlag`.
- Removed dozens of unused imports across the GUI, packages, tools and Utilities modules.
