#!/usr/bin/env python3
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

"""
Mock syz-manager TCP server for testing the syzkaller executor standalone.

This script replicates syz-manager's TCP protocol to communicate with the
executor's Runner process. It implements the full flatbuffers-based RPC
handshake and program execution flow, allowing isolated testing of the
executor without running the full Go-based syz-manager infrastructure.

Usage:
    # On the host machine (Python server):
    python3 syz_mock_manager.py --port 12345 --syscall-index 20

    # On the FreeBSD target machine (executor):
    ./syz-executor runner 0 <host-ip> 12345

Dependencies:
    pip install flatbuffers
"""

import argparse
import random
import signal
import socket
import struct
import sys
import time

import flatbuffers
import flatbuffers.builder
import flatbuffers.number_types
import flatbuffers.table
import flatbuffers.encode
import flatbuffers.packer

# =============================================================================
# Constants & Enums (from pkg/flatrpc/flatrpc.go)
# =============================================================================

# Feature flags (bit_flags)
FEATURE_COVERAGE = 1
FEATURE_COMPARISONS = 2
FEATURE_EXTRA_COVERAGE = 4
FEATURE_DELAY_KCOV_MMAP = 8
FEATURE_KCOV_RESET_IOCTL = 16
FEATURE_SANDBOX_NONE = 32
FEATURE_SANDBOX_SETUID = 64
FEATURE_SANDBOX_NAMESPACE = 128
FEATURE_SANDBOX_ANDROID = 256
FEATURE_FAULT = 512
FEATURE_LEAK = 1024
FEATURE_NET_INJECTION = 2048
FEATURE_NET_DEVICES = 4096
FEATURE_KCSAN = 8192
FEATURE_DEVLINK_PCI = 16384
FEATURE_NIC_VF = 32768
FEATURE_USB_EMULATION = 65536
FEATURE_VHCI_INJECTION = 131072
FEATURE_WIFI_EMULATION = 262144
FEATURE_LRWPAN_EMULATION = 524288
FEATURE_BINFMT_MISC = 1048576
FEATURE_SWAP = 2097152
FEATURE_MEMORY_DUMP = 4194304

# ExecEnv flags (bit_flags)
EXEC_ENV_DEBUG = 1
EXEC_ENV_SIGNAL = 2
EXEC_ENV_READ_ONLY_COVERAGE = 4
EXEC_ENV_RESET_STATE = 8
EXEC_ENV_SANDBOX_NONE = 16
EXEC_ENV_SANDBOX_SETUID = 32
EXEC_ENV_SANDBOX_NAMESPACE = 64
EXEC_ENV_SANDBOX_ANDROID = 128
EXEC_ENV_EXTRA_COVER = 256
EXEC_ENV_ENABLE_TUN = 512
EXEC_ENV_ENABLE_NET_DEV = 1024
EXEC_ENV_ENABLE_NET_RESET = 2048
EXEC_ENV_ENABLE_CGROUPS = 4096
EXEC_ENV_ENABLE_CLOSE_FDS = 8192
EXEC_ENV_ENABLE_DEVLINK_PCI = 16384
EXEC_ENV_ENABLE_VHCI_INJECTION = 32768
EXEC_ENV_ENABLE_WIFI = 65536
EXEC_ENV_DELAY_KCOV_MMAP = 131072
EXEC_ENV_ENABLE_NIC_VF = 262144

# ExecFlag flags (bit_flags)
EXEC_FLAG_COLLECT_SIGNAL = 1
EXEC_FLAG_COLLECT_COVER = 2
EXEC_FLAG_DEDUP_COVER = 4
EXEC_FLAG_COLLECT_COMPS = 8
EXEC_FLAG_THREADED = 16

# RequestType
REQUEST_TYPE_PROGRAM = 0
REQUEST_TYPE_BINARY = 1
REQUEST_TYPE_GLOB = 2

# RequestFlag (bit_flags)
REQUEST_FLAG_RETURN_OUTPUT = 1
REQUEST_FLAG_RETURN_ERROR = 2

# HostMessagesRaw union type discriminators
HOST_MSG_NONE = 0
HOST_MSG_EXEC_REQUEST = 1
HOST_MSG_SIGNAL_UPDATE = 2
HOST_MSG_CORPUS_TRIAGED = 3
HOST_MSG_STATE_REQUEST = 4

# ExecutorMessagesRaw union type discriminators
EXECUTOR_MSG_NONE = 0
EXECUTOR_MSG_EXEC_RESULT = 1
EXECUTOR_MSG_EXECUTING = 2
EXECUTOR_MSG_STATE = 3

# CallFlag (bit_flags)
CALL_FLAG_EXECUTED = 1
CALL_FLAG_FINISHED = 2
CALL_FLAG_BLOCKED = 4
CALL_FLAG_FAULT_INJECTED = 8
CALL_FLAG_COVERAGE_OVERFLOW = 16

# Executor program instruction constants (from executor.cc / encodingexec.go)
EXEC_INSTR_EOF = 0xFFFFFFFFFFFFFFFF
EXEC_NO_COPYOUT = 0xFFFFFFFFFFFFFFFF

# Auth hash primes (from executor_runner.h:686 and rpcserver.go:275)
AUTH_PRIME1 = 73856093
AUTH_PRIME2 = 83492791
UINT64_MASK = 0xFFFFFFFFFFFFFFFF

# =============================================================================
# Wire Protocol Helpers
# =============================================================================


def recv_exact(sock, n):
    """Read exactly n bytes from socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed while reading (got {len(buf)}/{n} bytes)")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock, builder):
    """Send a size-prefixed flatbuffer message from a finished builder."""
    data = bytes(builder.Output())
    sock.sendall(data)


def recv_msg(sock):
    """Receive a size-prefixed flatbuffer message, return payload bytes (without size prefix)."""
    size_bytes = recv_exact(sock, 4)
    size = struct.unpack('<I', size_bytes)[0]
    if size > 64 * 1024 * 1024:
        raise ValueError(f"Message size too large: {size}")
    payload = recv_exact(sock, size)
    return payload


def hexdump(data, prefix=""):
    """Print a hex dump of data."""
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i + 16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i + 16])
        print(f"{prefix}{i:04x}: {hex_part:<48s}  {ascii_part}")


# =============================================================================
# Varint Codec (Go-compatible zigzag + varint)
# =============================================================================


def zigzag_encode(v):
    """Zigzag encode a signed int64 to unsigned."""
    if v < 0:
        return ((~v) << 1) | 1
    return v << 1


def varint_encode(uv):
    """Encode an unsigned value as varint bytes."""
    buf = bytearray()
    while uv > 0x7F:
        buf.append((uv & 0x7F) | 0x80)
        uv >>= 7
    buf.append(uv & 0x7F)
    return bytes(buf)


def encode_exec_value(val):
    """Encode a uint64 value for executor program format.

    Matches Go's binary.AppendVarint(buf, int64(val)).
    The val parameter is treated as uint64 and reinterpreted as int64.
    """
    # Reinterpret uint64 as int64
    val = val & UINT64_MASK
    if val >= (1 << 63):
        ival = val - (1 << 64)
    else:
        ival = val
    return varint_encode(zigzag_encode(ival))


def self_test_varint():
    """Verify varint encoding against known values."""
    tests = [
        (0, b'\x00'),
        (1, b'\x02'),
        (0xFFFFFFFFFFFFFFFF, b'\x01'),  # -1 as int64
        (20, b'\x28'),
        (0xFFFFFFFFFFFFFFFE, b'\x03'),  # -2 as int64 (execInstrCopyin)
        (0xFFFFFFFFFFFFFFFD, b'\x05'),  # -3 as int64 (execInstrCopyout)
        (0xFFFFFFFFFFFFFFFC, b'\x07'),  # -4 as int64 (execInstrSetProps)
    ]
    for val, expected in tests:
        result = encode_exec_value(val)
        assert result == expected, \
            f"varint({val:#x}): got {result.hex()} expected {expected.hex()}"
    print("[OK] Varint self-test passed")


# =============================================================================
# Flatbuffer Table Parser (manual, no generated code)
# =============================================================================


def parse_root_table(buf):
    """Parse the root table from a flatbuffer payload (without size prefix)."""
    if len(buf) < 4:
        raise ValueError("Flatbuffer too short")
    root_off = struct.unpack_from('<I', buf, 0)[0]
    tab = flatbuffers.table.Table(bytearray(buf), root_off)
    return tab


def _field_offset(tab, field_index):
    """Get the field's offset relative to the table, or 0 if absent."""
    vtable_off = tab.Pos - tab.Get(flatbuffers.number_types.SOffsetTFlags, tab.Pos)
    vtable_size = tab.Get(flatbuffers.number_types.VOffsetTFlags, vtable_off)
    field_vt_off = 4 + field_index * 2
    if field_vt_off >= vtable_size:
        return 0
    field_off = tab.Get(flatbuffers.number_types.VOffsetTFlags, vtable_off + field_vt_off)
    return field_off


def get_uint8(tab, field_index, default=0):
    off = _field_offset(tab, field_index)
    if off:
        return tab.Get(flatbuffers.number_types.Uint8Flags, tab.Pos + off)
    return default


def get_bool(tab, field_index, default=False):
    return bool(get_uint8(tab, field_index, int(default)))


def get_int32(tab, field_index, default=0):
    off = _field_offset(tab, field_index)
    if off:
        return tab.Get(flatbuffers.number_types.Int32Flags, tab.Pos + off)
    return default


def get_uint64(tab, field_index, default=0):
    off = _field_offset(tab, field_index)
    if off:
        return tab.Get(flatbuffers.number_types.Uint64Flags, tab.Pos + off)
    return default


def get_int64(tab, field_index, default=0):
    off = _field_offset(tab, field_index)
    if off:
        return tab.Get(flatbuffers.number_types.Int64Flags, tab.Pos + off)
    return default


def get_string(tab, field_index, default=""):
    off = _field_offset(tab, field_index)
    if off:
        result = tab.String(tab.Pos + off)
        if result is not None:
            return result.decode('utf-8') if isinstance(result, bytes) else result
    return default


def get_bytes_vector(tab, field_index):
    """Get a [uint8] vector as bytes."""
    off = _field_offset(tab, field_index)
    if not off:
        return b""
    vec_off = tab.Indirect(tab.Pos + off)
    length = tab.Get(flatbuffers.number_types.UOffsetTFlags, vec_off)
    start = vec_off + flatbuffers.number_types.UOffsetTFlags.bytewidth
    return bytes(tab.Bytes[start:start + length])


def get_subtable(tab, field_index):
    """Get a sub-table (table field)."""
    off = _field_offset(tab, field_index)
    if not off:
        return None
    sub_off = tab.Indirect(tab.Pos + off)
    return flatbuffers.table.Table(tab.Bytes, sub_off)


def get_vector_of_tables(tab, field_index):
    """Get a vector of tables."""
    off = _field_offset(tab, field_index)
    if not off:
        return []
    vec_off = tab.Indirect(tab.Pos + off)
    length = tab.Get(flatbuffers.number_types.UOffsetTFlags, vec_off)
    tables = []
    elem_start = vec_off + flatbuffers.number_types.UOffsetTFlags.bytewidth
    for i in range(length):
        elem_pos = elem_start + i * 4
        elem_table_off = tab.Indirect(elem_pos)
        tables.append(flatbuffers.table.Table(tab.Bytes, elem_table_off))
    return tables


def get_uint64_vector(tab, field_index):
    """Get a [uint64] vector as a list of ints."""
    off = _field_offset(tab, field_index)
    if not off:
        return []
    vec_off = tab.Indirect(tab.Pos + off)
    length = tab.Get(flatbuffers.number_types.UOffsetTFlags, vec_off)
    start = vec_off + flatbuffers.number_types.UOffsetTFlags.bytewidth
    return [struct.unpack_from('<Q', tab.Bytes, start + i * 8)[0] for i in range(length)]


# =============================================================================
# Message Parsers
# =============================================================================


def parse_connect_request(payload):
    """Parse ConnectRequestRaw: cookie(0), id(1), arch(2), git_revision(3), syz_revision(4)"""
    tab = parse_root_table(payload)
    return {
        'cookie': get_uint64(tab, 0),
        'id': get_int64(tab, 1),
        'arch': get_string(tab, 2),
        'git_revision': get_string(tab, 3),
        'syz_revision': get_string(tab, 4),
    }


def parse_feature_info(tab):
    """Parse FeatureInfoRaw: id(0), need_setup(1), reason(2)"""
    return {
        'id': get_uint64(tab, 0),
        'need_setup': get_bool(tab, 1),
        'reason': get_string(tab, 2),
    }


def parse_file_info(tab):
    """Parse FileInfoRaw: name(0), exists(1), error(2), data(3)"""
    return {
        'name': get_string(tab, 0),
        'exists': get_bool(tab, 1),
        'error': get_string(tab, 2),
        'data': get_bytes_vector(tab, 3),
    }


def parse_info_request(payload):
    """Parse InfoRequestRaw: error(0), features(1), files(2)"""
    tab = parse_root_table(payload)
    return {
        'error': get_string(tab, 0),
        'features': [parse_feature_info(t) for t in get_vector_of_tables(tab, 1)],
        'files': [parse_file_info(t) for t in get_vector_of_tables(tab, 2)],
    }


def parse_call_info(tab):
    """Parse CallInfoRaw: flags(0), error(1), signal(2), cover(3), comps(4)"""
    if tab is None:
        return None
    return {
        'flags': get_uint8(tab, 0),
        'error': get_int32(tab, 1),
        'signal': get_uint64_vector(tab, 2),
        'cover': get_uint64_vector(tab, 3),
        # comps (vector of ComparisonRaw structs) omitted for simplicity
    }


def parse_prog_info(tab):
    """Parse ProgInfoRaw: calls(0), extra_raw(1), extra(2), elapsed(3), freshness(4)"""
    if tab is None:
        return None
    return {
        'calls': [parse_call_info(t) for t in get_vector_of_tables(tab, 0)],
        'extra_raw': [parse_call_info(t) for t in get_vector_of_tables(tab, 1)],
        'extra': parse_call_info(get_subtable(tab, 2)),
        'elapsed_ns': get_uint64(tab, 3),
        'freshness': get_uint64(tab, 4),
    }


def parse_executing(tab):
    """Parse ExecutingMessageRaw: id(0), proc_id(1), try(2), wait_duration(3)"""
    return {
        'type': 'Executing',
        'id': get_int64(tab, 0),
        'proc_id': get_int32(tab, 1),
        'try': get_int32(tab, 2),
        'wait_duration_ns': get_int64(tab, 3),
    }


def parse_exec_result(tab):
    """Parse ExecResultRaw: id(0), proc(1), output(2), hanged(3), error(4), info(5)"""
    return {
        'type': 'ExecResult',
        'id': get_int64(tab, 0),
        'proc': get_int32(tab, 1),
        'output': get_bytes_vector(tab, 2),
        'hanged': get_bool(tab, 3),
        'error': get_string(tab, 4),
        'info': parse_prog_info(get_subtable(tab, 5)),
    }


def parse_executor_message(payload):
    """Parse ExecutorMessageRaw: msg_type(0), msg(1) — union dispatch."""
    tab = parse_root_table(payload)
    msg_type = get_uint8(tab, 0)
    msg_tab = get_subtable(tab, 1)
    if msg_tab is None:
        return {'type': 'Unknown', 'msg_type': msg_type}
    if msg_type == EXECUTOR_MSG_EXEC_RESULT:
        return parse_exec_result(msg_tab)
    elif msg_type == EXECUTOR_MSG_EXECUTING:
        return parse_executing(msg_tab)
    elif msg_type == EXECUTOR_MSG_STATE:
        return {'type': 'State', 'data': get_bytes_vector(msg_tab, 0)}
    else:
        return {'type': 'Unknown', 'msg_type': msg_type}


# =============================================================================
# Flatbuffer Builders
# =============================================================================


def build_connect_hello(cookie):
    """Build ConnectHelloRaw: cookie(0)"""
    builder = flatbuffers.builder.Builder(64)
    builder.StartObject(1)
    builder.PrependUint64Slot(0, cookie, 0)
    hello = builder.EndObject()
    builder.FinishSizePrefixed(hello)
    return builder


def build_connect_reply(debug=True, cover=False, cover_edges=False, kernel_64_bit=True,
                        procs=1, slowdown=1, syscall_timeout_ms=5000,
                        program_timeout_ms=30000, features=FEATURE_SANDBOX_NONE,
                        files=None, leak_frames=None, race_frames=None):
    """Build ConnectReplyRaw: debug(0), cover(1), cover_edges(2), kernel_64_bit(3),
    procs(4), slowdown(5), syscall_timeout_ms(6), program_timeout_ms(7),
    leak_frames(8), race_frames(9), features(10), files(11)"""
    builder = flatbuffers.builder.Builder(1024)

    # Pre-create vectors/strings (must be done before StartObject)
    leak_frames_off = 0
    if leak_frames:
        str_offs = [builder.CreateString(s) for s in reversed(leak_frames)]
        builder.StartVector(4, len(leak_frames), 4)
        for off in str_offs:
            builder.PrependUOffsetTRelative(off)
        leak_frames_off = builder.EndVector()

    race_frames_off = 0
    if race_frames:
        str_offs = [builder.CreateString(s) for s in reversed(race_frames)]
        builder.StartVector(4, len(race_frames), 4)
        for off in str_offs:
            builder.PrependUOffsetTRelative(off)
        race_frames_off = builder.EndVector()

    files_off = 0
    if files:
        str_offs = [builder.CreateString(s) for s in reversed(files)]
        builder.StartVector(4, len(files), 4)
        for off in str_offs:
            builder.PrependUOffsetTRelative(off)
        files_off = builder.EndVector()

    builder.StartObject(12)
    builder.PrependBoolSlot(0, debug, False)
    builder.PrependBoolSlot(1, cover, False)
    builder.PrependBoolSlot(2, cover_edges, False)
    builder.PrependBoolSlot(3, kernel_64_bit, False)
    builder.PrependInt32Slot(4, procs, 0)
    builder.PrependInt32Slot(5, slowdown, 0)
    builder.PrependInt32Slot(6, syscall_timeout_ms, 0)
    builder.PrependInt32Slot(7, program_timeout_ms, 0)
    if leak_frames_off:
        builder.PrependUOffsetTRelativeSlot(8, leak_frames_off, 0)
    if race_frames_off:
        builder.PrependUOffsetTRelativeSlot(9, race_frames_off, 0)
    builder.PrependUint64Slot(10, features, 0)
    if files_off:
        builder.PrependUOffsetTRelativeSlot(11, files_off, 0)
    reply = builder.EndObject()
    builder.FinishSizePrefixed(reply)
    return builder


def build_info_reply(cover_filter=None):
    """Build InfoReplyRaw: cover_filter(0)"""
    builder = flatbuffers.builder.Builder(256)

    filter_off = 0
    if cover_filter:
        builder.StartVector(8, len(cover_filter), 8)
        for pc in reversed(cover_filter):
            builder.PrependUint64(pc)
        filter_off = builder.EndVector()

    builder.StartObject(1)
    if filter_off:
        builder.PrependUOffsetTRelativeSlot(0, filter_off, 0)
    info = builder.EndObject()
    builder.FinishSizePrefixed(info)
    return builder


def build_exec_request(req_id, prog_data, env_flags, exec_flags,
                       sandbox_arg=0, req_type=REQUEST_TYPE_PROGRAM,
                       avoid=0, flags=0, all_signal=None):
    """Build HostMessageRaw wrapping ExecRequestRaw.

    ExecRequestRaw fields: id(0), type(1), avoid(2), data(3), exec_opts(4), flags(5), all_signal(6)
    HostMessageRaw fields: msg_type(0), msg(1)
    """
    builder = flatbuffers.builder.Builder(4096)

    # Pre-create vectors
    data_off = builder.CreateByteVector(prog_data)

    all_signal_off = 0
    if all_signal:
        builder.StartVector(4, len(all_signal), 4)
        for s in reversed(all_signal):
            builder.PrependInt32(s)
        all_signal_off = builder.EndVector()

    # Build ExecRequestRaw table
    builder.StartObject(7)
    builder.PrependInt64Slot(0, req_id, 0)
    builder.PrependUint64Slot(1, req_type, 0)
    builder.PrependUint64Slot(2, avoid, 0)
    builder.PrependUOffsetTRelativeSlot(3, data_off, 0)
    # ExecOptsRaw struct (24 bytes inline, reverse field order)
    builder.Prep(8, 24)
    builder.PrependInt64(sandbox_arg)
    builder.PrependUint64(exec_flags)
    builder.PrependUint64(env_flags)
    builder.Slot(4)
    builder.PrependUint64Slot(5, flags, 0)
    if all_signal_off:
        builder.PrependUOffsetTRelativeSlot(6, all_signal_off, 0)
    exec_req = builder.EndObject()

    # Build HostMessageRaw wrapper (union)
    builder.StartObject(2)
    builder.PrependByteSlot(0, HOST_MSG_EXEC_REQUEST, 0)
    builder.PrependUOffsetTRelativeSlot(1, exec_req, 0)
    host_msg = builder.EndObject()

    builder.FinishSizePrefixed(host_msg)
    return builder


# =============================================================================
# Program Builder
# =============================================================================


def build_getpid_program(syscall_index):
    """Build a minimal program with a single syscall (0 args, no copyout).

    Format: [num_calls] [call_id] [copyout_idx] [num_args] [eof]
    """
    buf = bytearray()
    buf += encode_exec_value(1)                    # num_calls = 1
    buf += encode_exec_value(syscall_index)         # syscall index in executor table
    buf += encode_exec_value(EXEC_NO_COPYOUT)       # ExecNoCopyout = -1
    buf += encode_exec_value(0)                     # 0 arguments
    buf += encode_exec_value(EXEC_INSTR_EOF)        # execInstrEOF = -1
    return bytes(buf)


def build_program_with_args(syscall_index, const_args):
    """Build a program with a single syscall and constant arguments.

    Args:
        syscall_index: Index in the executor's syscall table.
        const_args: List of (value, size) tuples for constant arguments.
                    size is in bytes (1, 2, 4, or 8).
    """
    EXEC_INSTR_COPYIN = 0xFFFFFFFFFFFFFFFE
    ARG_CONST = 0

    buf = bytearray()
    buf += encode_exec_value(1)  # num_calls = 1

    # Emit copyin instructions for each argument that needs data setup
    # For simple constant args passed directly, no copyin is needed

    # Emit the syscall
    buf += encode_exec_value(syscall_index)
    buf += encode_exec_value(EXEC_NO_COPYOUT)
    buf += encode_exec_value(len(const_args))

    for value, size in const_args:
        # arg_const format: [type=0] [meta] [value]
        # meta = size | (format << 8) | (bf_off << 16) | (bf_len << 24) | (pid_stride << 32)
        meta = size  # native format, no bitfield
        buf += encode_exec_value(ARG_CONST)
        buf += encode_exec_value(meta)
        buf += encode_exec_value(value)

    buf += encode_exec_value(EXEC_INSTR_EOF)
    return bytes(buf)


# =============================================================================
# Pretty Printing
# =============================================================================


def format_call_flags(flags):
    """Format CallFlag bitmask as readable string."""
    parts = []
    if flags & CALL_FLAG_EXECUTED:
        parts.append("Executed")
    if flags & CALL_FLAG_FINISHED:
        parts.append("Finished")
    if flags & CALL_FLAG_BLOCKED:
        parts.append("Blocked")
    if flags & CALL_FLAG_FAULT_INJECTED:
        parts.append("FaultInjected")
    if flags & CALL_FLAG_COVERAGE_OVERFLOW:
        parts.append("CoverOverflow")
    return '|'.join(parts) if parts else "None"


def pretty_print_result(result):
    """Pretty-print an ExecResult message."""
    print(f"\n{'='*60}")
    print(f"ExecResult:")
    print(f"  id:     {result['id']}")
    print(f"  proc:   {result['proc']}")
    print(f"  hanged: {result['hanged']}")
    if result['error']:
        print(f"  error:  {result['error']}")
    if result['output']:
        print(f"  output: ({len(result['output'])} bytes)")
        try:
            text = result['output'].decode('utf-8', errors='replace')
            for line in text.strip().split('\n'):
                print(f"    | {line}")
        except Exception:
            pass

    info = result.get('info')
    if info:
        elapsed_ms = info['elapsed_ns'] / 1_000_000
        print(f"  elapsed:   {elapsed_ms:.2f} ms")
        print(f"  freshness: {info['freshness']}")

        for i, call in enumerate(info['calls']):
            if call is None:
                print(f"  call[{i}]: <empty>")
                continue
            flags_str = format_call_flags(call['flags'])
            print(f"  call[{i}]: flags={flags_str} errno={call['error']}")
            if call['signal']:
                print(f"    signal: {len(call['signal'])} entries")
                for j, sig in enumerate(call['signal'][:10]):
                    print(f"      [{j}] 0x{sig:016x}")
                if len(call['signal']) > 10:
                    print(f"      ... ({len(call['signal']) - 10} more)")
            if call['cover']:
                print(f"    cover: {len(call['cover'])} PCs")
                for j, pc in enumerate(call['cover'][:10]):
                    print(f"      [{j}] 0x{pc:016x}")
                if len(call['cover']) > 10:
                    print(f"      ... ({len(call['cover']) - 10} more)")

        if info['extra_raw']:
            print(f"  extra_raw: {len(info['extra_raw'])} entries")
        if info['extra']:
            extra = info['extra']
            print(f"  extra: flags={format_call_flags(extra['flags'])} "
                  f"signal={len(extra['signal'])} cover={len(extra['cover'])}")
    print(f"{'='*60}\n")


# =============================================================================
# Auth
# =============================================================================


def auth_hash(cookie):
    """Compute auth hash matching executor_runner.h HashAuthCookie and rpcserver.go authHash."""
    return ((cookie * AUTH_PRIME1) ^ AUTH_PRIME2) & UINT64_MASK


# =============================================================================
# Main Server
# =============================================================================


def do_handshake(conn, config, verbose=False):
    """Perform the full connection handshake. Returns connect_request info dict."""
    # Step 1: Send ConnectHello with random cookie
    cookie = random.getrandbits(64)
    expected_cookie = auth_hash(cookie)
    print(f"[Handshake] Sending ConnectHello (cookie=0x{cookie:016x})")
    builder = build_connect_hello(cookie)
    if verbose:
        hexdump(bytes(builder.Output()), "  TX: ")
    send_msg(conn, builder)

    # Step 2: Receive ConnectRequest
    print("[Handshake] Waiting for ConnectRequest...")
    payload = recv_msg(conn)
    if verbose:
        hexdump(payload, "  RX: ")
    req = parse_connect_request(payload)
    print(f"[Handshake] ConnectRequest received:")
    print(f"  cookie: 0x{req['cookie']:016x} (expected 0x{expected_cookie:016x})")
    print(f"  id:     {req['id']}")
    print(f"  arch:   {req['arch']}")
    print(f"  git_revision: {req['git_revision']}")
    print(f"  syz_revision: {req['syz_revision']}")

    if req['cookie'] != expected_cookie:
        raise ValueError(f"Cookie mismatch! Got 0x{req['cookie']:016x}, "
                         f"expected 0x{expected_cookie:016x}")
    print("[Handshake] Cookie verified OK")

    # Step 3: Send ConnectReply
    print(f"[Handshake] Sending ConnectReply (procs={config['procs']}, "
          f"features=0x{config['features']:x})")
    builder = build_connect_reply(
        debug=config['debug'],
        cover=config['cover'],
        cover_edges=config.get('cover_edges', False),
        kernel_64_bit=True,
        procs=config['procs'],
        slowdown=config['slowdown'],
        syscall_timeout_ms=config['syscall_timeout_ms'],
        program_timeout_ms=config['program_timeout_ms'],
        features=config['features'],
    )
    if verbose:
        hexdump(bytes(builder.Output()), "  TX: ")
    send_msg(conn, builder)

    # Step 4: Receive InfoRequest
    print("[Handshake] Waiting for InfoRequest...")
    payload = recv_msg(conn)
    if verbose:
        hexdump(payload, "  RX: ")
    info_req = parse_info_request(payload)
    print(f"[Handshake] InfoRequest received:")
    if info_req['error']:
        print(f"  ERROR: {info_req['error']}")
    for feat in info_req['features']:
        feat_name = f"0x{feat['id']:x}"
        status = "setup" if feat['need_setup'] else "no-setup"
        reason = f" ({feat['reason']})" if feat['reason'] else ""
        print(f"  Feature {feat_name}: {status}{reason}")
    for finfo in info_req['files']:
        print(f"  File {finfo['name']}: exists={finfo['exists']} "
              f"({len(finfo['data'])} bytes){' error=' + finfo['error'] if finfo['error'] else ''}")

    # Step 5: Send InfoReply
    print("[Handshake] Sending InfoReply (empty cover_filter)")
    builder = build_info_reply()
    if verbose:
        hexdump(bytes(builder.Output()), "  TX: ")
    send_msg(conn, builder)

    print("[Handshake] Complete!\n")
    return req


def execute_program(conn, req_id, prog_data, env_flags, exec_flags, config, verbose=False):
    """Send an exec request and receive the result."""
    flags = 0
    if config.get('return_output', True):
        flags |= REQUEST_FLAG_RETURN_OUTPUT
    flags |= REQUEST_FLAG_RETURN_ERROR

    all_signal = None
    if exec_flags & EXEC_FLAG_COLLECT_SIGNAL:
        # Request signal for all calls (call index 0 for a single-call program)
        all_signal = [0]

    print(f"[Exec] Sending ExecRequest id={req_id} "
          f"(env=0x{env_flags:x} exec=0x{exec_flags:x} "
          f"prog={len(prog_data)} bytes)")
    if verbose:
        print(f"  Program data: {prog_data.hex()}")

    builder = build_exec_request(
        req_id=req_id,
        prog_data=prog_data,
        env_flags=env_flags,
        exec_flags=exec_flags,
        flags=flags,
        all_signal=all_signal,
    )
    if verbose:
        hexdump(bytes(builder.Output()), "  TX: ")
    send_msg(conn, builder)

    # Receive messages until we get an ExecResult
    result = None
    while result is None:
        payload = recv_msg(conn)
        if verbose:
            hexdump(payload, "  RX: ")
        msg = parse_executor_message(payload)

        if msg['type'] == 'Executing':
            print(f"[Exec] Executing: id={msg['id']} proc={msg['proc_id']} "
                  f"try={msg['try']} wait={msg['wait_duration_ns']}ns")
        elif msg['type'] == 'ExecResult':
            result = msg
        else:
            print(f"[Exec] Unexpected message: {msg}")

    return result


def run_server(config):
    """Run the mock syz-manager server."""
    host = config['host']
    port = config['port']
    verbose = config.get('verbose', False)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)
    print(f"Mock syz-manager listening on {host}:{port}")
    print(f"Run on FreeBSD target: syz-executor runner 0 <this-host-ip> {port}")
    print(f"Waiting for connection...\n")

    # Handle Ctrl+C gracefully
    def sigint_handler(sig, frame):
        print("\nShutting down...")
        server_sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    conn, addr = server_sock.accept()
    print(f"Connection from {addr[0]}:{addr[1]}\n")
    conn.settimeout(config['program_timeout_ms'] / 1000 * 3)

    try:
        # Phase 1: Handshake
        connect_info = do_handshake(conn, config, verbose)

        # Phase 2: Execute test programs
        env_flags = config['env_flags']
        exec_flags = config['exec_flags']

        if config.get('cover', False):
            env_flags |= EXEC_ENV_SIGNAL

        syscall_index = config.get('syscall_index')
        if syscall_index is None:
            print("[WARN] No --syscall-index specified, skipping program execution.")
            print("Keeping connection alive for manual testing. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
            return

        num_runs = config.get('num_runs', 1)
        prog_data = build_getpid_program(syscall_index)

        print(f"\n--- Executing {num_runs} test program(s) ---")
        print(f"Syscall index: {syscall_index}")
        print(f"EnvFlags:  0x{env_flags:x}")
        print(f"ExecFlags: 0x{exec_flags:x}")
        print(f"Program:   {prog_data.hex()}")
        print()

        for i in range(num_runs):
            result = execute_program(conn, i + 1, prog_data, env_flags, exec_flags,
                                     config, verbose)
            pretty_print_result(result)

        print(f"\nAll {num_runs} program(s) executed successfully.")
        print("Closing connection.")

    except ConnectionError as e:
        print(f"\n[ERROR] Connection error: {e}")
    except socket.timeout:
        print(f"\n[ERROR] Socket timeout")
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()
        server_sock.close()


# =============================================================================
# CLI
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Mock syz-manager TCP server for testing syzkaller executor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic test with getpid (syscall index varies per build):
  %(prog)s --port 12345 --syscall-index 20

  # Test with coverage collection:
  %(prog)s --port 12345 --syscall-index 20 --cover --exec-flags 0x3

  # Verbose mode (hex dump all messages):
  %(prog)s --port 12345 --syscall-index 20 --verbose

  # Multiple runs:
  %(prog)s --port 12345 --syscall-index 20 --num-runs 5

On FreeBSD target, run:
  ./syz-executor runner 0 <host-ip> <port>
""",
    )
    parser.add_argument('--host', default='0.0.0.0',
                        help='Listen address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=12345,
                        help='Listen port (default: 12345)')
    parser.add_argument('--debug', action='store_true', default=True,
                        help='Enable executor debug output (default: true)')
    parser.add_argument('--no-debug', action='store_false', dest='debug',
                        help='Disable executor debug output')
    parser.add_argument('--cover', action='store_true', default=False,
                        help='Enable coverage collection')
    parser.add_argument('--procs', type=int, default=1,
                        help='Number of parallel procs (default: 1)')
    parser.add_argument('--slowdown', type=int, default=1,
                        help='Timeout slowdown factor (default: 1)')
    parser.add_argument('--syscall-timeout-ms', type=int, default=5000,
                        help='Per-syscall timeout in ms (default: 5000)')
    parser.add_argument('--program-timeout-ms', type=int, default=30000,
                        help='Per-program timeout in ms (default: 30000)')
    parser.add_argument('--syscall-index', type=int, default=None,
                        help='Syscall index in executor table for test program')
    parser.add_argument('--num-runs', type=int, default=1,
                        help='Number of test programs to execute (default: 1)')
    parser.add_argument('--env-flags', type=lambda x: int(x, 0),
                        default=EXEC_ENV_DEBUG | EXEC_ENV_SANDBOX_NONE,
                        help='ExecEnv bitmask (default: 0x11 = Debug|SandboxNone)')
    parser.add_argument('--exec-flags', type=lambda x: int(x, 0), default=0,
                        help='ExecFlag bitmask (default: 0x0)')
    parser.add_argument('--features', type=lambda x: int(x, 0),
                        default=FEATURE_SANDBOX_NONE,
                        help='Feature bitmask for ConnectReply (default: 0x20 = SandboxNone)')
    parser.add_argument('--verbose', action='store_true', default=False,
                        help='Hex-dump all sent/received messages')
    parser.add_argument('--return-output', action='store_true', default=True,
                        help='Request program output in results (default: true)')
    parser.add_argument('--self-test', action='store_true', default=False,
                        help='Run self-tests and exit')

    args = parser.parse_args()

    if args.self_test:
        self_test_varint()
        print("[OK] All self-tests passed")
        return

    config = {
        'host': args.host,
        'port': args.port,
        'debug': args.debug,
        'cover': args.cover,
        'cover_edges': False,
        'procs': args.procs,
        'slowdown': args.slowdown,
        'syscall_timeout_ms': args.syscall_timeout_ms,
        'program_timeout_ms': args.program_timeout_ms,
        'features': args.features,
        'syscall_index': args.syscall_index,
        'num_runs': args.num_runs,
        'env_flags': args.env_flags,
        'exec_flags': args.exec_flags,
        'verbose': args.verbose,
        'return_output': args.return_output,
    }

    self_test_varint()
    run_server(config)


if __name__ == '__main__':
    main()
