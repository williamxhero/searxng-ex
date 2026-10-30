# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline provenance gates; wheel/distribution fixtures are never installed or imported."""

# pylint: disable=missing-class-docstring,invalid-name

import base64
import csv
from hashlib import sha256
import importlib.metadata
import io
import os
import py_compile
from pathlib import Path
import sys
import sysconfig
import tempfile
from unittest import TestCase
from unittest.mock import patch
import zipfile

from wag_protection import contract


WORKSPACE = Path(__file__).resolve().parents[2]
WHEEL_NAME = "wag_provenance_fixture-1.2.3-py3-none-any.whl"
DIST_INFO = "wag_provenance_fixture-1.2.3.dist-info"
DIST_NAME = "wag-provenance-fixture"
PAYLOAD = "wag_provenance_fixture/__init__.py"
NATIVE_PAYLOAD = "wag_provenance_fixture/backend.abi3.so"
NATIVE_FILES = (
    "wag_protection/__init__.py",
    "wag_protection/ledger.py",
    "wag_protection/contract.py",
    "searx/data/engine_traits.json",
    "searx/engines/__init__.py",
    "searx/settings.yml",
    "searx/settings_defaults.py",
    "searx/settings_loader.py",
    "searx/network/__init__.py",
    "searx/network/client.py",
    "searx/network/network.py",
    "searx/network/protected.py",
    "searx/search/__init__.py",
    "searx/search/processors/abstract.py",
    "searx/search/processors/online.py",
    "searx/results.py",
    "searx/webutils.py",
    "searx/webapp.py",
    "searx/exceptions.py",
    "searx/utils.py",
    "searx/engines/quark.py",
)


class DependencyProvenanceTest(TestCase):  # pylint: disable=too-many-public-methods
    def setUp(self):
        # Real, disposable distribution metadata, not a new runtime dependency.
        self.temporary = tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
            prefix="provenance-", dir=WORKSPACE
        )
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.site = self.directory / "site"
        self.site.mkdir()
        self.scripts = self.directory / "bin"
        self.launcher = self.scripts / "fixture-cli"
        self.wheel = self.directory / WHEEL_NAME
        self.payload = {
            PAYLOAD: b'"""Never imported test fixture."""\n',
            NATIVE_PAYLOAD: b"not executable: native byte identity fixture\n",
            DIST_INFO + "/METADATA": b"Metadata-Version: 2.1\nName: wag-provenance-fixture\nVersion: 1.2.3\n",
            DIST_INFO + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        }
        self._write_wheel()
        self._write_installed()
        real_distribution = importlib.metadata.distribution

        def distribution(name):
            if name == DIST_NAME:
                return importlib.metadata.PathDistribution(self.site / DIST_INFO)
            return real_distribution(name)

        self.addCleanup(patch.stopall)
        patch.object(importlib.metadata, "distribution", side_effect=distribution).start()

    def _record(self):
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        for name, contents in self.payload.items():
            digest = base64.urlsafe_b64encode(sha256(contents).digest()).rstrip(b"=").decode("ascii")
            writer.writerow([name, "sha256=" + digest, len(contents)])
        writer.writerow([DIST_INFO + "/RECORD", "", ""])
        return out.getvalue().encode("utf-8")

    def _write_wheel(self):
        with zipfile.ZipFile(self.wheel, "w") as archive:
            for name, contents in self.payload.items():
                archive.writestr(name, contents)
            archive.writestr(DIST_INFO + "/RECORD", self._record())

    def _write_installed(self):
        for name, contents in {
            **self.payload,
            DIST_INFO + "/RECORD": self._record(),
        }.items():
            path = self.site / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)

    def _manifest(self, mode="production"):
        files = {name: sha256((WORKSPACE / name).read_bytes()).hexdigest() for name in NATIVE_FILES}
        wheel_path = str(self.wheel.relative_to(WORKSPACE))
        files[wheel_path] = sha256(self.wheel.read_bytes()).hexdigest()
        registry = [
            {
                "engine": "quark",
                "domestic": True,
                "module": "quark",
                "capability": "online_one_send",
                "source_digest": files["searx/engines/quark.py"],
                "profile": {"live_hold": True},
                "aliases": ["quark"],
            }
        ]
        python = Path(sys.executable).resolve()
        manifest = {
            "schema": "wag.protection-artifact.v2",
            "contract": "wag.outbound.v2",
            "mode": mode,
            "fork_commit": "9" * 40,
            "artifact_digest": "0" * 64,
            "registry_digest": contract.json_digest(registry),
            "config_digest": "a" * 64,
            "python_digest": sha256(python.read_bytes()).hexdigest(),
            "module_root": str(WORKSPACE),
            "python_executable": str(python),
            "root": str(contract.PRODUCTION_ROOT if mode == "production" else self.directory / "state"),
            "shared_gid": 1000,
            "allowed_uids": sorted({0, os.getuid()}),
            "files": files,
            "distributions": {DIST_NAME: "1.2.3"},
            "wheels": {WHEEL_NAME: files[wheel_path]},
            "registry": registry,
        }
        return self._seal(manifest)

    @staticmethod
    def _seal(manifest):
        manifest["registry_digest"] = contract.json_digest(manifest["registry"])
        manifest["artifact_digest"] = contract.json_digest({key: manifest[key] for key in contract.ARTIFACT_FIELDS})
        return manifest

    def _validate(self, manifest):
        return contract.validate_manifest(manifest, Path(manifest["root"]), manifest["mode"])

    def test_production_rejects_empty_inventories(self):
        for missing in ("distributions", "wheels", "both"):
            with self.subTest(missing=missing):
                manifest = self._manifest()
                for key in ("distributions", "wheels") if missing == "both" else (missing,):
                    manifest[key] = {}
                with self.assertRaises(ValueError):
                    self._validate(self._seal(manifest))

    def test_synthetic_preserves_empty_inventories(self):
        manifest = self._manifest("synthetic")
        manifest.update(distributions={}, wheels={})
        approved = self._validate(self._seal(manifest))
        self.assertEqual(approved["distributions"], {})
        self.assertEqual(approved["wheels"], {})

    def test_production_accepts_verified_wheel_and_installed_payload(self):
        manifest = self._manifest()
        self.assertEqual(self._validate(manifest), manifest)
        self.assertTrue(manifest["registry"][0]["profile"]["live_hold"])

    def test_production_accepts_explicitly_approved_installation_outputs(self):
        installer = self.site / DIST_INFO / "INSTALLER"
        installer.write_bytes(b"pip\n")
        requested = self.site / DIST_INFO / "REQUESTED"
        requested.write_bytes(b"")
        bytecode = Path(py_compile.compile(str(self.site / PAYLOAD), doraise=True))
        record = self.site / DIST_INFO / "RECORD"
        # pip preserves shipped payload but rewrites RECORD for generated files.
        record.write_bytes(
            self._record()
            + (DIST_INFO + "/INSTALLER,,\n" + DIST_INFO + "/REQUESTED,,\n").encode()
            + (str(bytecode.relative_to(self.site)) + ",,\n").encode()
        )
        manifest = self._manifest()
        for path in (installer, requested, bytecode, record):
            manifest["files"][str(path.relative_to(WORKSPACE))] = sha256(path.read_bytes()).hexdigest()
        manifest = self._seal(manifest)
        self.assertEqual(self._validate(manifest), manifest)
        for path in (installer, requested, bytecode, record):
            with self.subTest(unapproved=path.name):
                relative = str(path.relative_to(WORKSPACE))
                expected = manifest["files"].pop(relative)
                with self.assertRaises(ValueError):
                    self._validate(self._seal(manifest))
                manifest["files"][relative] = expected
        self._seal(manifest)
        bytecode.write_bytes(b"unapproved executable bytecode")
        with self.assertRaises(ValueError):
            self._validate(manifest)

    def test_production_rejects_changed_wheel_payload_even_in_installed_inventory(self):
        path = self.site / NATIVE_PAYLOAD
        path.write_bytes(b"changed executable payload")
        manifest = self._manifest()
        manifest["files"][str(path.relative_to(WORKSPACE))] = sha256(path.read_bytes()).hexdigest()
        # An installed-artifact hash cannot override the wheel's shipped code.
        with self.assertRaises(ValueError):
            self._validate(self._seal(manifest))

    def _console_manifest(self, entry_points=b"[console_scripts]\nfixture-cli = wag_provenance_fixture:main\n"):
        self.payload[DIST_INFO + "/entry_points.txt"] = entry_points
        self._write_wheel()
        self._write_installed()
        self.scripts.mkdir()
        launcher = self.launcher
        # Actual Linux pip/distlib launcher shape, not imported or executed.
        launcher.write_text(
            f"#!{sys.executable}\n"
            "# -*- coding: utf-8 -*-\n"
            "import re\n"
            "import sys\n"
            "from wag_provenance_fixture import main\n"
            "if __name__ == '__main__':\n"
            "    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])\n"
            "    sys.exit(main())\n",
            encoding="utf-8",
        )
        record = self.site / DIST_INFO / "RECORD"
        with record.open("a", encoding="utf-8") as output:
            output.write(os.path.relpath(launcher, self.site) + ",,\n")
        manifest = self._manifest()
        manifest["files"][str(record.relative_to(WORKSPACE))] = sha256(record.read_bytes()).hexdigest()
        manifest = self._seal(manifest)
        return manifest

    def test_production_accepts_wheel_declared_console_launcher(self):
        manifest = self._console_manifest()
        with patch.object(sysconfig, "get_path", return_value=str(self.scripts)):
            self.assertEqual(self._validate(manifest), manifest)

    def test_production_accepts_console_launcher_with_empty_defaults(self):
        manifest = self._console_manifest(
            b"[DEFAULT]\n\n[console_scripts]\nfixture-cli = wag_provenance_fixture:main\n"
        )
        with patch.object(sysconfig, "get_path", return_value=str(self.scripts)):
            self.assertEqual(self._validate(manifest), manifest)

    def test_production_rejects_console_launcher_inherited_from_defaults(self):
        manifest = self._console_manifest(
            b"[DEFAULT]\nfixture-cli = wag_provenance_fixture:main\n\n[console_scripts]\n"
        )
        with patch.object(sysconfig, "get_path", return_value=str(self.scripts)):
            with self.assertRaisesRegex(ValueError, "wheel entry points defaults"):
                self._validate(manifest)

    def test_production_rejects_modified_console_launcher_body_or_interpreter(self):
        manifest = self._console_manifest()
        original = self.launcher.read_bytes()
        variants = (
            original.replace(b"import main", b"import other"),
            original.replace(sys.executable.encode(), b"/unapproved/python"),
            original + b"# appended executable content\n",
        )
        with patch.object(sysconfig, "get_path", return_value=str(self.scripts)):
            for contents in variants:
                with self.subTest(contents=contents):
                    self.launcher.write_bytes(contents)
                    with self.assertRaisesRegex(ValueError, "installed launcher mismatch"):
                        self._validate(manifest)
        self.launcher.write_bytes(original)

    def test_production_rejects_noncanonical_console_record_paths(self):
        manifest = self._console_manifest()
        record = self.site / DIST_INFO / "RECORD"
        original = record.read_text(encoding="utf-8")
        expected = os.path.relpath(self.launcher, self.site)
        variants = (
            expected.replace("fixture-cli", "unapproved-cli"),
            "../bin/../bin/fixture-cli",
            str(self.launcher),
        )
        with patch.object(sysconfig, "get_path", return_value=str(self.scripts)):
            for name in variants:
                with self.subTest(record_path=name):
                    record.write_text(original.replace(expected, name), encoding="utf-8")
                    manifest["files"][str(record.relative_to(WORKSPACE))] = sha256(record.read_bytes()).hexdigest()
                    with self.assertRaises(ValueError):
                        self._validate(self._seal(manifest))

    def test_production_rejects_missing_or_symlink_console_launcher(self):
        manifest = self._console_manifest()
        original = self.launcher.read_bytes()
        self.launcher.unlink()
        with patch.object(sysconfig, "get_path", return_value=str(self.scripts)):
            with self.assertRaises((OSError, ValueError)):
                self._validate(manifest)
            target = self.scripts / "other-cli"
            target.write_bytes(original)
            self.launcher.symlink_to(target)
            with self.assertRaises(ValueError):
                self._validate(manifest)

    def test_production_rejects_missing_or_duplicate_console_record_entry(self):
        manifest = self._console_manifest()
        record = self.site / DIST_INFO / "RECORD"
        original = record.read_text(encoding="utf-8")
        row = os.path.relpath(self.launcher, self.site) + ",,\n"
        with patch.object(sysconfig, "get_path", return_value=str(self.scripts)):
            for contents in (original.replace(row, ""), original + row):
                with self.subTest(record=contents):
                    record.write_text(contents, encoding="utf-8")
                    manifest["files"][str(record.relative_to(WORKSPACE))] = sha256(record.read_bytes()).hexdigest()
                    with self.assertRaises(ValueError):
                        self._validate(self._seal(manifest))

    def test_production_accepts_canonical_wheel_directory_entries(self):
        with zipfile.ZipFile(self.wheel, "a") as archive:
            archive.writestr("wag_provenance_fixture/", b"")
            archive.writestr(DIST_INFO + "/", b"")
        manifest = self._manifest()
        self.assertEqual(self._validate(manifest), manifest)

    def test_production_rejects_unsafe_wheel_directories_and_special_files(self):
        original = self.wheel.read_bytes()
        entries = (
            ("../outside/", 0o040000, b""),
            ("/outside/", 0o040000, b""),
            ("wag_provenance_fixture//", 0o040000, b""),
            ("wag_provenance_fixture/", 0o120000, b""),
            ("wag_provenance_fixture/", 0o100000, b""),
            ("wag_provenance_fixture/", 0o040000, b"unexpected directory contents"),
            (PAYLOAD + "/", 0o040000, b""),
            ("unexpected_fifo", 0o010000, b""),
        )
        for name, file_type, contents in entries:
            with self.subTest(name=name, file_type=file_type, contents=contents):
                self.wheel.write_bytes(original)
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (file_type | 0o755) << 16
                with zipfile.ZipFile(self.wheel, "a") as archive:
                    archive.writestr(info, contents)
                with self.assertRaises(ValueError):
                    self._validate(self._manifest())

    def test_production_rejects_duplicate_wheel_file_entries(self):
        with zipfile.ZipFile(self.wheel, "a") as archive:
            with self.assertWarns(UserWarning):
                archive.writestr(PAYLOAD, self.payload[PAYLOAD])
        with self.assertRaises(ValueError):
            self._validate(self._manifest())

    def test_production_rejects_arbitrary_bytes_with_a_wheel_name(self):
        self.wheel.write_bytes(b"not a ZIP wheel")
        with self.assertRaises(ValueError):
            self._validate(self._manifest())

    def test_production_rejects_wheel_without_distribution(self):
        manifest = self._manifest()
        manifest["distributions"] = {"httpx": importlib.metadata.version("httpx")}
        with self.assertRaises(ValueError):
            self._validate(self._seal(manifest))

    def test_production_rejects_uncovered_distribution(self):
        manifest = self._manifest()
        manifest["distributions"]["httpx"] = importlib.metadata.version("httpx")
        with self.assertRaises(ValueError):
            self._validate(self._seal(manifest))

    def test_production_rejects_wrong_installed_version(self):
        (self.site / DIST_INFO / "METADATA").write_bytes(
            self.payload[DIST_INFO + "/METADATA"].replace(b"1.2.3", b"9.9.9")
        )
        with self.assertRaises(ValueError):
            self._validate(self._manifest())

    def test_production_rejects_missing_installed_distribution(self):
        with patch.object(
            importlib.metadata,
            "distribution",
            side_effect=importlib.metadata.PackageNotFoundError,
        ):
            with self.assertRaises((ValueError, importlib.metadata.PackageNotFoundError)):
                self._validate(self._manifest())

    def test_production_rejects_same_version_different_installed_bytes(self):
        for name in (PAYLOAD, NATIVE_PAYLOAD, DIST_INFO + "/WHEEL"):
            with self.subTest(file=name):
                self._write_installed()
                (self.site / name).write_bytes(b"unapproved replacement bytes")
                with self.assertRaises(ValueError):
                    self._validate(self._manifest())

    def test_production_rejects_missing_installed_payload(self):
        (self.site / NATIVE_PAYLOAD).unlink()
        with self.assertRaises((ValueError, OSError)):
            self._validate(self._manifest())

    def test_production_rejects_wheel_metadata_mismatch(self):
        self.payload[DIST_INFO + "/METADATA"] = self.payload[DIST_INFO + "/METADATA"].replace(b"1.2.3", b"9.9.9")
        self._write_wheel()
        self._write_installed()
        manifest = self._manifest()
        manifest["distributions"][DIST_NAME] = "9.9.9"
        with self.assertRaises(ValueError):
            self._validate(self._seal(manifest))

    def test_production_rejects_missing_installed_record(self):
        (self.site / DIST_INFO / "RECORD").unlink()
        with self.assertRaises(ValueError):
            self._validate(self._manifest())

    def test_production_rejects_undeclared_installed_payload(self):
        (self.site / DIST_INFO / "RECORD").write_bytes(self._record() + b"extra_backend.so,,\n")
        (self.site / "extra_backend.so").write_bytes(b"not approved")
        with self.assertRaises(ValueError):
            self._validate(self._manifest())

    def test_production_rejects_unbacked_wheel_digest(self):
        manifest = self._manifest()
        manifest["wheels"][WHEEL_NAME] = "f" * 64
        with self.assertRaises(ValueError):
            self._validate(self._seal(manifest))

    def test_production_rejects_wheel_file_outside_files_inventory(self):
        manifest = self._manifest()
        del manifest["files"][str(self.wheel.relative_to(WORKSPACE))]
        with self.assertRaises(ValueError):
            self._validate(self._seal(manifest))

    def test_production_rejects_wheel_tampering_without_reapproval(self):
        manifest = self._manifest()
        self.wheel.write_bytes(b"replaced approved artifact")
        with self.assertRaises(ValueError):
            self._validate(manifest)

    def test_production_rejects_symlink_installed_payload(self):
        path = self.site / PAYLOAD
        path.unlink()
        path.symlink_to(self.site / NATIVE_PAYLOAD)
        with self.assertRaises(ValueError):
            self._validate(self._manifest())

    def test_production_preserves_quark_hold(self):
        manifest = self._manifest()
        manifest["registry"][0]["profile"]["live_hold"] = False
        with self.assertRaisesRegex(ValueError, "quark must remain held"):
            self._validate(self._seal(manifest))
