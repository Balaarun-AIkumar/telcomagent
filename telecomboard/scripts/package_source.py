"""Make a manual-upload archive from checked Git candidates, excluding local secrets."""
from zipfile import ZIP_DEFLATED, ZipFile

from check_secrets import ROOT, candidates, scan


def main() -> None:
    paths = [p for p in candidates() if p.is_file()]
    findings = scan(paths)
    if findings:
        raise SystemExit("Refusing to package files:\n" + "\n".join(findings))
    output = ROOT / "output" / "github" / "switchboard-source.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path, path.relative_to(ROOT).as_posix())
    with ZipFile(output) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
        assert {"README.md", ".gitignore", ".env.example", "pyproject.toml"} <= names
        assert not any(n == ".env" or n.startswith((".venv/", ".sbdata/", ".pytest_codex_tmp", "tmp/"))
                       for n in names)
    print(f"Packaged {len(paths)} checked files: {output}")


if __name__ == "__main__":
    main()
