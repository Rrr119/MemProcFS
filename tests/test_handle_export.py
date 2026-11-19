"""Tests for files/handle_export.py.

The native vmmpyc module only ships as a compiled binary on supported Windows
installations, so these tests drive the exporter through lightweight fakes
that mirror the public Python binding surface:

* vmm.process(pid_or_name) -> a process object;
* process.pid / process.name / process.is_wow64;
* process.maps.handle() -> list of handle dicts (as produced by
  VmmPycProcessMaps_handle in vmmpyc/vmmpyc_processmaps.c).

Run with:  python -m unittest discover -s tests -v
"""

import json
import os
import sys
import tempfile
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "files"))

import handle_export  # noqa: E402


def make_handle(handle, handle_type, tag="", access=0x1f0001, va_object=0x87654321):
    """Build one handle dict with the same keys as the vmmpyc binding."""
    return {
        "va-object": va_object,
        "handle": handle,
        "access": access,
        "typeindex": 0,
        "pid": 0,
        "pooltag": 0,
        "chandle": 1,
        "cpointer": 1,
        "va-object-creatinfo": 0,
        "va-securitydescriptor": 0,
        "tag": tag,
        "type": handle_type,
    }


class FakeMaps:
    def __init__(self, handles, fail=False):
        self._handles = handles
        self._fail = fail

    def handle(self):
        if self._fail:
            raise RuntimeError("VmmProcessMaps.handle(): Failed.")
        return list(self._handles)


class FakeProcess:
    def __init__(self, pid, name, handles, is_wow64=False, maps_fail=False):
        self.pid = pid
        self.name = name
        self.is_wow64 = is_wow64
        self.maps = FakeMaps(handles, fail=maps_fail)


class FakeVmm:
    """Minimal stand-in for memprocfs.Vmm used by the exporter."""

    def __init__(self, processes):
        self._processes = {p.pid: p for p in processes}
        self._by_name = {p.name: p for p in processes}
        self.closed = False

    def process(self, identifier):
        if isinstance(identifier, int) and identifier in self._processes:
            return self._processes[identifier]
        if isinstance(identifier, str) and identifier in self._by_name:
            return self._by_name[identifier]
        raise RuntimeError("Vmm.process(): Failed.")

    def close(self):
        self.closed = True


def build_vmm():
    native_handles = [
        make_handle(0x0004, "Process", tag="explorer.exe"),
        make_handle(0x0008, "Thread"),
        make_handle(0x000C, "File", tag=r"\Device\HarddiskVolume2\Windows\system32\ntdll.dll"),
        make_handle(0x0010, "Key", tag=r"\REGISTRY\MACHINE\SOFTWARE\Microsoft"),
        make_handle(0x0014, "File", tag=r"\Device\HarddiskVolume2\Windows\system32\kernel32.dll"),
        make_handle(0x0018, "Token"),
        make_handle(0x001C, "Desktop"),
    ]
    wow64_handles = [
        make_handle(0x0030, "File", tag=r"\Device\HarddiskVolume2\Windows\SysWOW64\ntdll.dll"),
        make_handle(0x0034, "Key", tag=r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node"),
        make_handle(0x0038, "Mutant", tag=r"\Sessions\1\BaseNamedObjects\wow_mutex"),
    ]
    native = FakeProcess(4321, "svchost.exe", native_handles, is_wow64=False)
    wow64 = FakeProcess(31337, "wow32app.exe", wow64_handles, is_wow64=True)
    return FakeVmm([native, wow64]), native, wow64


class EnumerateHandlesTests(unittest.TestCase):
    def setUp(self):
        self.vmm, self.native, self.wow64 = build_vmm()

    def test_enumerate_returns_all_handles_for_pid(self):
        handles = handle_export.enumerate_handles(self.vmm, pid=self.native.pid)
        self.assertEqual(len(handles), 7)
        self.assertEqual([h["handle"] for h in handles],
                         [0x0004, 0x0008, 0x000C, 0x0010, 0x0014, 0x0018, 0x001C])
        self.assertTrue(all("type" in h and "tag" in h for h in handles))

    def test_enumerate_supports_process_name(self):
        handles = handle_export.enumerate_handles(self.vmm, name=self.native.name)
        self.assertEqual(len(handles), 7)

    def test_enumerate_unknown_pid_raises(self):
        with self.assertRaises(handle_export.HandleExportError):
            handle_export.enumerate_handles(self.vmm, pid=9999)

    def test_enumerate_without_target_raises(self):
        with self.assertRaises(handle_export.HandleExportError):
            handle_export.enumerate_handles(self.vmm)

    def test_enumerate_propagates_map_failure(self):
        broken = FakeProcess(1, "broken.exe", [], maps_fail=True)
        vmm = FakeVmm([broken])
        with self.assertRaises(handle_export.HandleExportError):
            handle_export.enumerate_handles(vmm, pid=1)


class FilterHandlesTests(unittest.TestCase):
    def setUp(self):
        self.vmm, self.native, self.wow64 = build_vmm()

    def test_no_filter_keeps_every_entry(self):
        handles = handle_export.enumerate_handles(self.vmm, pid=self.native.pid)
        self.assertEqual(handle_export.filter_handles_by_type(handles, None), handles)

    def test_single_type_filter(self):
        handles = handle_export.enumerate_handles(self.vmm, pid=self.native.pid)
        files = handle_export.filter_handles_by_type(handles, "File")
        self.assertEqual([h["handle"] for h in files], [0x000C, 0x0014])
        self.assertTrue(all(h["type"] == "File" for h in files))

    def test_filter_is_case_insensitive(self):
        handles = handle_export.enumerate_handles(self.vmm, pid=self.native.pid)
        self.assertEqual(
            len(handle_export.filter_handles_by_type(handles, "file")), 2)
        self.assertEqual(
            len(handle_export.filter_handles_by_type(handles, "FILE")), 2)

    def test_filter_accepts_list_and_comma_separated_string(self):
        handles = handle_export.enumerate_handles(self.vmm, pid=self.native.pid)
        from_list = handle_export.filter_handles_by_type(handles, ["File", "Key"])
        from_string = handle_export.filter_handles_by_type(handles, "file, key")
        expected = [0x000C, 0x0010, 0x0014]
        self.assertEqual([h["handle"] for h in from_list], expected)
        self.assertEqual([h["handle"] for h in from_string], expected)

    def test_filter_unknown_type_returns_empty(self):
        handles = handle_export.enumerate_handles(self.vmm, pid=self.native.pid)
        self.assertEqual(handle_export.filter_handles_by_type(handles, "Semaphore"), [])


class JsonExportTests(unittest.TestCase):
    def setUp(self):
        self.vmm, self.native, self.wow64 = build_vmm()

    def test_report_envelope_fields(self):
        report = handle_export.build_report(self.vmm, pid=self.native.pid)
        self.assertEqual(report["version"], handle_export.HANDLE_EXPORT_VERSION)
        self.assertEqual(report["pid"], self.native.pid)
        self.assertEqual(report["name"], "svchost.exe")
        self.assertFalse(report["wow64"])
        self.assertIsNone(report["type_filter"])
        self.assertEqual(report["count"], 7)
        self.assertEqual(len(report["handles"]), 7)

    def test_report_records_applied_filter(self):
        report = handle_export.build_report(
            self.vmm, pid=self.native.pid, types=["Key", "File"])
        self.assertEqual(report["type_filter"], ["file", "key"])
        self.assertEqual(report["count"], 3)
        self.assertTrue(all(h["type"] in ("Key", "File") for h in report["handles"]))

    def test_export_to_json_string_is_valid_json(self):
        payload = handle_export.export_handles_json(
            self.vmm, pid=self.native.pid, types="File")
        self.assertIsInstance(payload, str)
        report = json.loads(payload)
        self.assertEqual(report["count"], 2)
        self.assertTrue(all(h["type"] == "File" for h in report["handles"]))

    def test_export_to_file_writes_utf8_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "handles.json")
            report = handle_export.export_handles_json(
                self.vmm, name=self.native.name, output_path=path)
            self.assertTrue(os.path.isfile(path))
            with open(path, "r", encoding="utf-8") as f:
                on_disk = json.load(f)
        self.assertEqual(on_disk, report)
        self.assertEqual(on_disk["pid"], self.native.pid)


class Wow64ProcessTests(unittest.TestCase):
    """32-bit (WoW64) process test: handle tables use the 32-bit parser path
    in vmm/vmmwin.c, so the exporter must still report every handle and flag
    the process correctly."""

    def setUp(self):
        self.vmm, self.native, self.wow64 = build_vmm()

    def test_wow64_process_is_marked_32bit(self):
        report = handle_export.build_report(self.vmm, pid=self.wow64.pid)
        self.assertTrue(report["wow64"])
        self.assertEqual(report["name"], "wow32app.exe")

    def test_wow64_full_enumeration(self):
        handles = handle_export.enumerate_handles(self.vmm, pid=self.wow64.pid)
        self.assertEqual(len(handles), 3)
        self.assertEqual(
            [h["handle"] for h in handles], [0x0030, 0x0034, 0x0038])

    def test_wow64_type_filter_and_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wow64_handles.json")
            report = handle_export.export_handles_json(
                self.vmm, pid=self.wow64.pid, types=["File", "Mutant"],
                output_path=path)
            with open(path, "r", encoding="utf-8") as f:
                on_disk = json.load(f)
        self.assertTrue(on_disk["wow64"])
        self.assertEqual(on_disk["count"], 2)
        self.assertEqual(
            sorted(h["type"] for h in on_disk["handles"]),
            ["File", "Mutant"])
        self.assertEqual(
            [h["handle"] for h in on_disk["handles"]], [0x0030, 0x0038])
        self.assertEqual(report["handles"], on_disk["handles"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.vmm, _, self.wow64 = build_vmm()

    def _fake_memprocfs(self):
        class FakeModule:
            Vmm = lambda *a, **kw: self.vmm  # noqa: E731

        return FakeModule

    def test_main_writes_filtered_json_file_and_closes_vmm(self):
        sys.modules["memprocfs"] = self._fake_memprocfs()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cli.json")
            argv = ["-device", "dummy.pmem", "-pid", str(self.wow64.pid),
                    "-type", "Key", "-out", path]
            handle_export.main(argv)
            with open(path, "r", encoding="utf-8") as f:
                report = json.load(f)
        self.assertTrue(report["wow64"])
        self.assertEqual(report["count"], 1)
        self.assertEqual(report["handles"][0]["type"], "Key")
        self.assertTrue(self.vmm.closed)
        del sys.modules["memprocfs"]


if __name__ == "__main__":
    unittest.main(verbosity=2)
