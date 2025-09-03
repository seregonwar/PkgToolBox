# Changelog

All notable changes to this project will be documented in this file.

## [1.4.0] - 2025-09-03

### Added
- PFS Info: introduced a dedicated tab `PfsInfoTab` (`GraphicUserInterface/widgets/pfs_info_tab.py`) to inspect PS4 PKG PFS structure via `shadPKG`.
- Sidebar Navigation: added a new sidebar entry "🧩 PFS Info" wired to the new tab for quick access.
- JSON Output Option: toggle to output `pfs-info` in JSON for future structured viewers.

### Changed
- Extract Tab UI: removed the inline PFS Info controls from `ExtractTab` to avoid duplication and to improve log readability. `ExtractTab` now focuses solely on extraction.
- Main Window Integration: updated `GraphicUserInterface/main_window.py` to import, instantiate, and register the PFS Info tab in the tab stack and sidebar.

### Improved
- Responsiveness: `pfs-info` tasks run asynchronously using `QThread`, preventing UI blocking and ensuring smooth updates in the output view.
- UX Consistency: consistent modern styling across the new tab and sidebar, maintaining the modular architecture.

### Notes
- Ensure `shadPKG.exe` is present (e.g., under `packages/ps3lib/`) for PFS Info to work.
- Tested with PS4 PKG flows; PS5/PS3 paths remain unchanged.

---


