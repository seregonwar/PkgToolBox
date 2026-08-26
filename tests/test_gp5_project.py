import json
from pathlib import Path

import pytest

from packages import GP4Project, GP5Project, StandaloneFileSource, open_source
from packages.exceptions import PackageFormatError


def _write_param(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "titleId": "PPSA12345",
        "contentId": "UP0000-PPSA12345_00-PKGTOOLBOXTEST00",
        "contentVersion": "01.000.000",
        "localizedParameters": {"en-US": {"titleName": "GP5 Test"}},
    }), encoding="utf-8")


def test_flat_gp5_resolves_sdk_relative_paths_and_reports_missing(tmp_path):
    _write_param(tmp_path / "sce_sys" / "param.json")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "hello.txt").write_text("hello", encoding="utf-8")
    project_path = tmp_path / "PPSA12345.gp5"
    project_path.write_text("""<?xml version="1.0" encoding="utf-8"?>
<psproject fmt="gp5" version="1000">
  <volume>
    <volume_type>prospero_app</volume_type>
    <package content_id="UP0000-PPSA12345_00-PKGTOOLBOXTEST00"
             passcode="00000000000000000000000000000000"/>
    <chunk_info chunk_count="1" scenario_count="1"/>
  </volume>
  <files>
    <file dst_path="\\sce_sys\\param.json" src_path="\\sce_sys\\param.json"/>
    <file dst_path="\\data\\hello.txt" src_path="\\data\\hello.txt"/>
    <file dst_path="\\missing.bin" src_path="\\missing.bin"/>
  </files>
</psproject>""", encoding="utf-8")

    project = open_source(str(project_path))

    assert isinstance(project, GP5Project)
    assert project.title_id == "PPSA12345"
    assert project.title_name == "GP5 Test"
    assert project.layout == "flat"
    assert project.read_file(1) == b"hello"
    assert project.get_info()["missing_files"] == 1
    assert project.files[2]["state"] == "Missing"


def test_rootdir_gp5_walks_folders_and_applies_excludes(tmp_path):
    source = tmp_path / "prepared"
    _write_param(source / "sce_sys" / "param.json")
    (source / "data").mkdir()
    (source / "data" / "keep.bin").write_bytes(b"ok")
    (source / "data" / "old.gp5").write_text("skip", encoding="utf-8")
    (source / "about").mkdir()
    (source / "about" / "scratch.bin").write_bytes(b"skip")
    project_path = tmp_path / "normal.gp5"
    project_path.write_text(f"""<psproject fmt="gp5" version="1000">
  <volume><volume_type>prospero_app</volume_type><package/></volume>
  <global_exclude>*.esbak</global_exclude>
  <rootdir src_path="{source}" dir_exclude="about" file_exclude="*.gp5"/>
</psproject>""", encoding="utf-8")

    project = GP5Project(str(project_path))
    names = {entry["name"] for entry in project.files.values()}

    assert project.layout == "rootdir"
    assert "data/keep.bin" in names
    assert "data/old.gp5" not in names
    assert "about/scratch.bin" not in names
    assert "sce_sys/param.json" in names


def test_gp5_rejects_entities_and_unsafe_destinations(tmp_path):
    entity_project = tmp_path / "entity.gp5"
    entity_project.write_text("""<!DOCTYPE x [<!ENTITY y "boom">]>
<psproject fmt="gp5"><volume><volume_type>&y;</volume_type></volume></psproject>""",
                              encoding="utf-8")
    with pytest.raises(PackageFormatError, match="DTD/entity"):
        GP5Project(str(entity_project))

    unsafe = tmp_path / "unsafe.gp5"
    unsafe.write_text("""<psproject fmt="gp5"><volume><volume_type>prospero_app</volume_type></volume>
<files><file dst_path="../escape.bin" src_path="missing.bin"/></files></psproject>""",
                      encoding="utf-8")
    with pytest.raises(PackageFormatError, match="unsafe GP5 destination"):
        GP5Project(str(unsafe))


def test_gp4_and_standalone_files_share_the_source_api(tmp_path):
    payload = tmp_path / "eboot.bin"
    payload.write_bytes(b"ELF preview")
    gp4_path = tmp_path / "CUSA12345.gp4"
    gp4_path.write_text(f"""<psproject fmt="gp4" version="1000">
  <volume>
    <volume_type>pkg_ps4_app</volume_type>
    <package content_id="UP0000-CUSA12345_00-PKGTOOLBOXTEST00"
             passcode="00000000000000000000000000000000"/>
    <chunk_info chunk_count="1" scenario_count="1"/>
  </volume>
  <files><file targ_path="eboot.bin" orig_path="{payload}"/></files>
  <rootdir/>
</psproject>""", encoding="utf-8")

    project = open_source(str(gp4_path))
    standalone = open_source(str(payload))

    assert isinstance(project, GP4Project)
    assert project.get_info()["platform"] == "PS4"
    assert project.read_file(0) == b"ELF preview"
    assert isinstance(standalone, StandaloneFileSource)
    assert standalone.get_info()["source_type"] == "Standalone File"
    assert standalone.read_file(0) == b"ELF preview"
