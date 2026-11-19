#!/usr/bin/env python3
"""Per-process handle enumeration, type filtering and JSON export for MemProcFS.

This module wraps the native handle map exposed by the vmmpyc Python binding
(``VmmProcess.maps.handle()``) and adds the forensics workflow pieces that are
not part of the core API:

* enumeration of every handle held by one process;
* case-insensitive filtering by object manager type (e.g. ``File``, ``Key``,
  ``Process``, ``Thread``, ``Token`` ...);
* deterministic JSON export, either to a file or as a serializable dict.

The core functions take an already initialized ``memprocfs.Vmm`` instance so
they can be used both from other scripts and from the command line:

    import memprocfs
    from handle_export import export_handles_json

    vmm = memprocfs.Vmm(["-device", "c:\\dumps\\win10.pmem"])
    report = export_handles_json(vmm, 1234, "handles.json", types=["File"])

Command line:

    python handle_export.py -device win10.pmem -pid 1234 -type File -type Key
"""

import argparse
import json


HANDLE_EXPORT_VERSION = 1


class HandleExportError(RuntimeError):
    """Raised when a process or its handle map cannot be retrieved."""


def _resolve_process(vmm, pid=None, name=None):
    """Fetch a VmmProcess by PID (preferred) or by process name."""
    try:
        if pid is not None:
            return vmm.process(int(pid))
        if name is not None:
            return vmm.process(name)
    except (RuntimeError, ValueError) as e:
        raise HandleExportError("Failed to resolve process: %s" % e)
    raise HandleExportError("Either a PID or a process name must be specified.")


def _normalize_types(types):
    """Turn a str/list/None filter spec into a set of lowercase type names."""
    if types is None:
        return None
    if isinstance(types, str):
        types = types.split(",")
    normalized = set()
    for entry in types:
        if entry is None:
            continue
        entry = str(entry).strip()
        if entry:
            normalized.add(entry.lower())
    return normalized or None


def enumerate_handles(vmm, pid=None, name=None):
    """Enumerate all handles owned by one process.

    Keyword arguments:
    -- vmm       = memprocfs.Vmm: initialized VMM instance.
    -- pid       = int: PID of the target process.
    -- name      = str: optional process name, used when pid is not given.
    -- return    = list[dict]: raw handle entries from maps.handle().
    """
    process = _resolve_process(vmm, pid=pid, name=name)
    try:
        handles = process.maps.handle()
    except RuntimeError as e:
        raise HandleExportError("Failed to enumerate handles: %s" % e)
    if not isinstance(handles, list):
        raise HandleExportError("Unexpected handle map type: %s" % type(handles).__name__)
    return handles


def filter_handles_by_type(handles, types):
    """Filter handle entries by object manager type (case-insensitive).

    Keyword arguments:
    -- handles = list[dict]: entries as returned by enumerate_handles().
    -- types   = str | list[str] | None: a single type, a comma separated
                 string, a list of types, or None to keep every entry.
    -- return  = list[dict]: matching entries in their original order.
    """
    wanted = _normalize_types(types)
    if wanted is None:
        return list(handles)
    result = []
    for handle in handles:
        handle_type = str(handle.get("type") or "").strip().lower()
        if handle_type in wanted:
            result.append(handle)
    return result


def build_report(vmm, pid=None, name=None, types=None):
    """Build a JSON-serializable handle report for one process.

    Keyword arguments:
    -- vmm    = memprocfs.Vmm: initialized VMM instance.
    -- pid    = int: PID of the target process.
    -- name   = str: optional process name, used when pid is not given.
    -- types  = str | list[str] | None: optional type filter.
    -- return = dict: report envelope (also written by export_handles_json()).
    """
    process = _resolve_process(vmm, pid=pid, name=name)
    wanted = _normalize_types(types)
    handles = filter_handles_by_type(enumerate_handles(vmm, process.pid), wanted)
    return {
        "version": HANDLE_EXPORT_VERSION,
        "pid": process.pid,
        "name": process.name,
        "wow64": bool(getattr(process, "is_wow64", False)),
        "type_filter": sorted(wanted) if wanted is not None else None,
        "count": len(handles),
        "handles": handles,
    }


def export_handles_json(vmm, pid=None, name=None, types=None, output_path=None, indent=2):
    """Enumerate, filter and export the handles of one process as JSON.

    Keyword arguments:
    -- vmm         = memprocfs.Vmm: initialized VMM instance.
    -- pid         = int: PID of the target process.
    -- name        = str: optional process name, used when pid is not given.
    -- types       = str | list[str] | None: optional type filter.
    -- output_path = str: optional file path; when omitted JSON is returned as
                     a string instead of being written to disk.
    -- indent      = int: json.dump indentation level.
    -- return      = dict | str: the report dict when output_path is given,
                     otherwise the serialized JSON string.
    """
    report = build_report(vmm, pid=pid, name=name, types=types)
    if output_path is None:
        return json.dumps(report, indent=indent, sort_keys=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=indent, sort_keys=True)
        f.write("\n")
    return report


def main(argv=None):
    """Command line entry point."""
    parser = argparse.ArgumentParser(
        description="Enumerate handles of a process in a memory dump and export them as JSON.")
    parser.add_argument("-device", dest="device", required=True,
                        help="LeechCore device spec, e.g. a .raw/.pmem memory dump path.")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-pid", dest="pid", type=int, help="Target process PID.")
    target.add_argument("-name", dest="name", help="Target process image name.")
    parser.add_argument("-type", dest="types", action="append", default=None,
                        help="Only keep handles of this object type (repeatable or comma separated).")
    parser.add_argument("-out", dest="output_path", default=None,
                        help="Output JSON file path (stdout when omitted).")
    args = parser.parse_args(argv)

    import memprocfs

    vmm = memprocfs.Vmm(["-device", args.device])
    try:
        if args.output_path is None:
            print(export_handles_json(
                vmm, pid=args.pid, name=args.name, types=args.types))
        else:
            report = export_handles_json(
                vmm, pid=args.pid, name=args.name, types=args.types,
                output_path=args.output_path)
            print("Exported %d handle(s) for PID %d to %s"
                  % (report["count"], report["pid"], args.output_path))
    finally:
        vmm.close()


if __name__ == "__main__":
    main()
