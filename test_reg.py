import os
import tempfile
import shutil
import pytest


@pytest.fixture
def work_dir(tmp_path, monkeypatch):
    """Create a temporary working directory and cd into it."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def load_x():
    """Import just the x() function without executing it."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("reg", os.path.join(os.path.dirname(__file__), "reg.py"))
    mod = importlib.util.module_from_spec(spec)
    # Prevent the top-level x() call from running during import
    source = open(spec.origin).read()
    source = source.replace("\nx()", "\n# x()")
    exec(compile(source, spec.origin, "exec"), mod.__dict__)
    return mod.x


# ---------------------------------------------------------------------------
# Core functionality
# ---------------------------------------------------------------------------

class TestBasicMerge:
    def test_merges_single_file(self, work_dir):
        (work_dir / "a.txt").write_text("hello\n", encoding="utf-8")
        x = load_x()
        x()
        output = (work_dir / "marchiori_lul.txt").read_text(encoding="utf-8")
        assert "hello" in output

    def test_merges_multiple_files(self, work_dir):
        (work_dir / "a.txt").write_text("aaa\n", encoding="utf-8")
        (work_dir / "b.txt").write_text("bbb\n", encoding="utf-8")
        x = load_x()
        x()
        output = (work_dir / "marchiori_lul.txt").read_text(encoding="utf-8")
        assert "aaa" in output
        assert "bbb" in output

    def test_files_separated_by_newline(self, work_dir):
        (work_dir / "a.txt").write_text("aaa", encoding="utf-8")
        (work_dir / "b.txt").write_text("bbb", encoding="utf-8")
        x = load_x()
        x()
        output = (work_dir / "marchiori_lul.txt").read_text(encoding="utf-8")
        # Each file's content should be followed by a newline separator
        assert "aaa\n" in output
        assert "bbb\n" in output

    def test_source_files_deleted_after_merge(self, work_dir):
        (work_dir / "a.txt").write_text("hello\n", encoding="utf-8")
        x = load_x()
        x()
        assert not (work_dir / "a.txt").exists()

    def test_output_file_not_consumed_as_input(self, work_dir):
        (work_dir / "marchiori_lul.txt").write_text("existing\n", encoding="utf-8")
        (work_dir / "a.txt").write_text("new\n", encoding="utf-8")
        x = load_x()
        x()
        output = (work_dir / "marchiori_lul.txt").read_text(encoding="utf-8")
        assert "existing" in output
        assert "new" in output


# ---------------------------------------------------------------------------
# Encoding handling
# ---------------------------------------------------------------------------

class TestEncodingHandling:
    def test_utf8_file(self, work_dir):
        (work_dir / "a.txt").write_text("café\n", encoding="utf-8")
        x = load_x()
        x()
        output = (work_dir / "marchiori_lul.txt").read_text(encoding="utf-8")
        assert "café" in output

    def test_latin1_fallback(self, work_dir):
        # Write a file that is valid Latin-1 but invalid UTF-8
        (work_dir / "a.txt").write_bytes(b"caf\xe9\n")
        x = load_x()
        x()
        output = (work_dir / "marchiori_lul.txt").read_text(encoding="utf-8")
        assert "caf" in output


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_directory(self, work_dir):
        x = load_x()
        x()
        assert not (work_dir / "marchiori_lul.txt").exists()

    def test_no_txt_files(self, work_dir):
        (work_dir / "readme.md").write_text("not a txt")
        x = load_x()
        x()
        assert not (work_dir / "marchiori_lul.txt").exists()

    def test_empty_txt_file(self, work_dir):
        (work_dir / "empty.txt").write_text("", encoding="utf-8")
        x = load_x()
        x()
        assert (work_dir / "marchiori_lul.txt").exists()

    def test_append_mode_accumulates(self, work_dir):
        """Running x() twice should append, not overwrite."""
        (work_dir / "a.txt").write_text("first\n", encoding="utf-8")
        x = load_x()
        x()
        (work_dir / "b.txt").write_text("second\n", encoding="utf-8")
        x()
        output = (work_dir / "marchiori_lul.txt").read_text(encoding="utf-8")
        assert "first" in output
        assert "second" in output

    def test_non_txt_files_ignored(self, work_dir):
        (work_dir / "data.csv").write_text("csv content")
        (work_dir / "a.txt").write_text("txt content\n", encoding="utf-8")
        x = load_x()
        x()
        output = (work_dir / "marchiori_lul.txt").read_text(encoding="utf-8")
        assert "csv content" not in output
        assert "txt content" in output
