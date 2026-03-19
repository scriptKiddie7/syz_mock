// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <arpa/inet.h>
#include <endian.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <new>
#include <setjmp.h>
#include <vector>

// SYZ_RPC_DIAG: Enable RPC diagnostic mode for debugging message corruption.
// When enabled (compile with -DSYZ_RPC_DIAG=1):
//   - CRC32 checksum verification on every received message (requires host-side
//     rpcDiagCRC=true in pkg/flatrpc/conn.go to send checksums)
//   - Full diagnostic dump on first corruption (memory, fds, TCP socket, proc state)
//   - Clean exit after first corruption so manager restarts fresh
//   - Message counter and recent size ring buffer for correlation
// When disabled (default): no overhead, existing behavior unchanged.
// IMPORTANT: Both executor and host must agree on SYZ_RPC_DIAG state.
#ifndef SYZ_RPC_DIAG
#define SYZ_RPC_DIAG 0
#endif

// Maximum size of a single RPC message (size-prefixed flatbuffer payload).
// ConnectReply can carry files (executor binary, etc.) so allow up to 64 MiB.
// Any message larger than this is almost certainly a corrupted size prefix.
static constexpr size_t kMaxRpcMessageSize = 64 << 20;

// Recovery state for bad_alloc during flatbuffer UnPackTo.
// Corrupt flatbuffers can pass the Verifier (which checks structural integrity)
// but still trigger multi-GB allocations during unpacking when vector length
// fields are corrupt. This is common when fuzzer-generated syscalls corrupt
// kernel TCP/memory state.
// When BadAllocHandler detects recv_unpack_active_, it longjmps back to the
// Recv method instead of aborting, allowing the runner to skip the corrupt
// message and continue fuzzing.
static jmp_buf recv_unpack_jmpbuf_;
static bool recv_unpack_active_ = false;
static const char* recv_unpack_data_ = nullptr;
static size_t recv_unpack_size_ = 0;

#if SYZ_RPC_DIAG
// CRC32 (ISO 3309 / ITU-T V.42, same polynomial as zlib / Go's crc32.ChecksumIEEE).
// Bit-by-bit implementation — no lookup table, compact code.
// Performance is fine for diagnostic use (called once per RPC message).
static uint32_t syz_crc32(const void* data, size_t len)
{
	const uint8_t* p = static_cast<const uint8_t*>(data);
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; i++) {
		crc ^= p[i];
		for (int j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
	}
	return crc ^ 0xFFFFFFFF;
}

// Diagnostic state — tracked per-connection for corruption analysis.
static uint64_t recv_msg_count_ = 0;                // total messages received
static constexpr size_t kRecentSizeCount = 16;
static uint32_t recv_recent_sizes_[kRecentSizeCount] = {};  // ring buffer of recent message sizes
static uint64_t recv_connect_time_ms_ = 0;           // timestamp when connection was established

// Corruption event details (set by Recv, read by Runner::Loop for diagnostic dump).
enum RecvCorruptionType {
	kCorruptNone = 0,
	kCorruptCrcMismatch,     // CRC32 mismatch — network/kernel TCP corruption
	kCorruptBadAllocUnpack,  // bad_alloc during UnPackTo — corrupt vector lengths
	kCorruptBadAllocResize,  // bad_alloc during recv_buf_.resize — memory exhaustion
};
static RecvCorruptionType recv_corruption_type_ = kCorruptNone;
static uint32_t recv_crc_expected_ = 0;
static uint32_t recv_crc_actual_ = 0;
#endif

// Connection represents a client TCP connection.
// It connects to the given addr:port and allows to send/receive
// flatbuffers-encoded messages.
class Connection
{
public:
	Connection(const char* addr, const char* port)
	    : fd_(Connect(addr, port))
	{
#if SYZ_RPC_DIAG
		recv_connect_time_ms_ = current_time_ms();
#endif
	}

	int FD() const
	{
		return fd_;
	}

	template <typename Msg>
	void Send(const Msg& msg)
	{
		typedef typename Msg::TableType Raw;
		auto off = Raw::Pack(fbb_, &msg);
		fbb_.FinishSizePrefixed(off);
		auto data = fbb_.GetBufferSpan();
		Send(data.data(), data.size());
		fbb_.Reset();
	}

	template <typename Msg>
	bool Recv(Msg& msg)
	{
		typedef typename Msg::TableType Raw;
		flatbuffers::uoffset_t size;
		Recv(&size, sizeof(size));
		size = le32toh(size);
		if (size == 0 || size > kMaxRpcMessageSize)
			failmsg("rpc message size out of range", "size=%u max=%zu", size, kMaxRpcMessageSize);
#if SYZ_RPC_DIAG
		recv_msg_count_++;
		recv_recent_sizes_[(recv_msg_count_ - 1) % kRecentSizeCount] = size;
		recv_corruption_type_ = kCorruptNone;
#endif
		// Set up recovery for bad_alloc during buffer resize or UnPackTo.
		// The fuzzer can corrupt kernel memory/TCP state, causing either:
		// (a) recv_buf_.resize(size) to fail even with a valid-looking size
		// (b) UnPackTo to hit bogus vector lengths that passed the Verifier
		// In both cases, longjmp back here, skip the message, continue fuzzing.
		recv_unpack_size_ = size;
		recv_unpack_data_ = nullptr;
		recv_unpack_active_ = true;
		if (setjmp(recv_unpack_jmpbuf_) != 0) {
			recv_unpack_active_ = false;
			if (recv_unpack_data_) {
				// bad_alloc during UnPackTo — hex dump the corrupt data.
				char hex[128 * 3 + 1] = {};
				size_t dump_len = std::min<size_t>(recv_unpack_size_, 128);
				for (size_t i = 0; i < dump_len; i++)
					snprintf(hex + i * 3, 4, "%02x ",
						 static_cast<unsigned char>(recv_unpack_data_[i]));
				debug("rpc recv: bad_alloc during unpack, skipping corrupt "
				      "message size=%zu hex=[%s]\n",
				      recv_unpack_size_, hex);
#if SYZ_RPC_DIAG
				recv_corruption_type_ = kCorruptBadAllocUnpack;
#endif
			} else {
				// bad_alloc during recv_buf_.resize — buffer not yet filled.
				// The message body (recv_unpack_size_ bytes) is still unread
				// in the TCP socket. Drain it to resynchronize the stream,
				// otherwise the next Recv reads body bytes as a size prefix.
				debug("rpc recv: bad_alloc during buffer resize, draining "
				      "message size=%zu\n",
				      recv_unpack_size_);
				char drain_buf[4096];
				size_t remaining = recv_unpack_size_;
				while (remaining > 0) {
					size_t chunk = std::min<size_t>(remaining, sizeof(drain_buf));
					Recv(drain_buf, chunk);
					remaining -= chunk;
				}
				debug("rpc recv: drained %zu bytes, stream resynchronized\n",
				      recv_unpack_size_);
#if SYZ_RPC_DIAG
				recv_corruption_type_ = kCorruptBadAllocResize;
#endif
			}
			return false;
		}
		recv_buf_.resize(size);
		Recv(recv_buf_.data(), size);
		recv_unpack_data_ = recv_buf_.data();
#if SYZ_RPC_DIAG
		// CRC32 verification: read the 4-byte checksum appended by the host
		// (pkg/flatrpc/conn.go with rpcDiagCRC=true), compute CRC32 of the
		// payload, and compare. A mismatch definitively proves network or
		// kernel TCP corruption (not a host serialization bug).
		{
			uint32_t expected_crc;
			Recv(&expected_crc, sizeof(expected_crc));
			expected_crc = le32toh(expected_crc);
			uint32_t actual_crc = syz_crc32(recv_buf_.data(), size);
			if (expected_crc != actual_crc) {
				recv_corruption_type_ = kCorruptCrcMismatch;
				recv_crc_expected_ = expected_crc;
				recv_crc_actual_ = actual_crc;
				recv_unpack_active_ = false;
				char hex[64 * 3 + 1] = {};
				size_t dump_len = std::min<size_t>(size, 64);
				for (size_t i = 0; i < dump_len; i++)
					snprintf(hex + i * 3, 4, "%02x ",
						 static_cast<unsigned char>(recv_buf_[i]));
				debug("rpc recv: CRC32 MISMATCH size=%u expected=0x%08x actual=0x%08x "
				      "msg#=%llu hex=[%s]\n",
				      size, expected_crc, actual_crc,
				      (unsigned long long)recv_msg_count_, hex);
				return false;
			}
		}
#endif
		// Verify the flatbuffer integrity before unpacking to prevent
		// corrupt vector lengths from causing multi-GB allocation attempts.
		// Use check_alignment=false to avoid cross-language (Go→C++) false positives.
		flatbuffers::Verifier::Options vopts;
		vopts.check_alignment = false;
		flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(recv_buf_.data()), size, vopts);
		if (!verifier.VerifyBuffer<Raw>()) {
			char hex[128 * 3 + 1] = {};
			size_t dump_len = std::min<size_t>(size, 128);
			for (size_t i = 0; i < dump_len; i++)
				snprintf(hex + i * 3, 4, "%02x ",
					 static_cast<unsigned char>(recv_buf_[i]));
			failmsg("rpc message flatbuffer verification failed",
				"size=%u hex=[%s]", size, hex);
		}
		auto raw = flatbuffers::GetRoot<Raw>(recv_buf_.data());
		debug("rpc recv: size=%u unpacking\n", size);
		raw->UnPackTo(&msg);
		recv_unpack_active_ = false;
		debug("rpc recv: unpack done\n");
		return true;
	}

#if SYZ_RPC_DIAG
	// Dump all connection-level diagnostic info to stderr.
	// Called from Runner on first corruption before bailing out.
	void DumpRecvDiagnostics() const
	{
		uint64_t uptime_ms = current_time_ms() - recv_connect_time_ms_;
		fprintf(stderr, "\n=== SYZ_RPC_DIAG: CONNECTION DIAGNOSTICS ===\n");
		fprintf(stderr, "uptime_ms: %llu\n", (unsigned long long)uptime_ms);
		fprintf(stderr, "total_messages_received: %llu\n", (unsigned long long)recv_msg_count_);
		fprintf(stderr, "recv_buf_capacity: %zu\n", recv_buf_.capacity());
		fprintf(stderr, "corruption_type: %d (%s)\n", recv_corruption_type_,
			recv_corruption_type_ == kCorruptCrcMismatch ? "CRC32_MISMATCH" :
			recv_corruption_type_ == kCorruptBadAllocUnpack ? "BAD_ALLOC_UNPACK" :
			recv_corruption_type_ == kCorruptBadAllocResize ? "BAD_ALLOC_RESIZE" : "NONE");
		fprintf(stderr, "corrupt_message_size: %zu\n", recv_unpack_size_);
		if (recv_corruption_type_ == kCorruptCrcMismatch) {
			fprintf(stderr, "crc_expected: 0x%08x\n", recv_crc_expected_);
			fprintf(stderr, "crc_actual: 0x%08x\n", recv_crc_actual_);
		}
		// Recent message sizes (ring buffer).
		fprintf(stderr, "--- Recent Message Sizes (last %zu) ---\n", kRecentSizeCount);
		size_t count = std::min<size_t>(recv_msg_count_, kRecentSizeCount);
		for (size_t i = 0; i < count; i++) {
			size_t idx = (recv_msg_count_ - count + i) % kRecentSizeCount;
			fprintf(stderr, "  [%zu]: %u\n", i, recv_recent_sizes_[idx]);
		}
		// TCP socket info.
		fprintf(stderr, "--- TCP Socket (fd=%d) ---\n", fd_);
		int so_err = 0;
		socklen_t olen = sizeof(so_err);
		if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &so_err, &olen) == 0)
			fprintf(stderr, "SO_ERROR: %d\n", so_err);
		int rcvbuf = 0;
		olen = sizeof(rcvbuf);
		if (getsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &olen) == 0)
			fprintf(stderr, "SO_RCVBUF: %d\n", rcvbuf);
		int sndbuf = 0;
		olen = sizeof(sndbuf);
		if (getsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &sndbuf, &olen) == 0)
			fprintf(stderr, "SO_SNDBUF: %d\n", sndbuf);
	}
#endif

	void Send(const void* data, size_t size)
	{
		for (size_t sent = 0; sent < size;) {
			ssize_t n = write(fd_, static_cast<const char*>(data) + sent, size - sent);
			if (n > 0) {
				sent += n;
				continue;
			}
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				sleep_ms(1);
				continue;
			}
			failmsg("failed to send rpc", "fd=%d want=%zu sent=%zu n=%zd", fd_, size, sent, n);
		}
	}

private:
	const int fd_;
	std::vector<char> recv_buf_;
	flatbuffers::FlatBufferBuilder fbb_;

	void Recv(void* data, size_t size)
	{
		for (size_t recv = 0; recv < size;) {
			ssize_t n = read(fd_, static_cast<char*>(data) + recv, size - recv);
			if (n > 0) {
				recv += n;
				continue;
			}
			if (n == 0) {
				// EOF — manager closed the connection (normal VM shutdown).
				// Don't exit or SYZFAIL — just sleep forever and let the
				// manager kill the VM externally. Exiting would drop the SSH
				// session and trigger a false "lost connection" crash report.
				debug("connection closed by manager (EOF), waiting for shutdown\n");
				for (;;)
					sleep(100);
			}
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				sleep_ms(1);
				continue;
			}
			failmsg("failed to recv rpc", "fd=%d want=%zu recv=%zu n=%zd", fd_, size, recv, n);
		}
	}

	static int Connect(const char* addr, const char* ports)
	{
		int port = atoi(ports);
		bool localhost = !strcmp(addr, "localhost");
		int fd;
		if (!strcmp(addr, "stdin"))
			return STDIN_FILENO;
		if (port == 0)
			failmsg("failed to parse manager port", "port=%s", ports);
		sockaddr_in saddr4 = {};
		saddr4.sin_family = AF_INET;
		saddr4.sin_port = htons(port);
		if (localhost)
			addr = "127.0.0.1";
		if (inet_pton(AF_INET, addr, &saddr4.sin_addr)) {
			fd = Connect(&saddr4, &saddr4.sin_addr, port);
			if (fd != -1 || !localhost)
				return fd;
		}
		sockaddr_in6 saddr6 = {};
		saddr6.sin6_family = AF_INET6;
		saddr6.sin6_port = htons(port);
		if (localhost)
			addr = "0:0:0:0:0:0:0:1";
		if (inet_pton(AF_INET6, addr, &saddr6.sin6_addr)) {
			fd = Connect(&saddr6, &saddr6.sin6_addr, port);
			if (fd != -1 || !localhost)
				return fd;
		}
		auto* hostent = gethostbyname(addr);
		if (!hostent)
			failmsg("failed to resolve manager addr", "addr=%s h_errno=%d", addr, h_errno);
		for (char** addr = hostent->h_addr_list; *addr; addr++) {
			if (hostent->h_addrtype == AF_INET) {
				memcpy(&saddr4.sin_addr, *addr, std::min<size_t>(hostent->h_length, sizeof(saddr4.sin_addr)));
				fd = Connect(&saddr4, &saddr4.sin_addr, port);
			} else if (hostent->h_addrtype == AF_INET6) {
				memcpy(&saddr6.sin6_addr, *addr, std::min<size_t>(hostent->h_length, sizeof(saddr6.sin6_addr)));
				fd = Connect(&saddr6, &saddr6.sin6_addr, port);
			} else {
				failmsg("unknown socket family", "family=%d", hostent->h_addrtype);
			}
			if (fd != -1)
				return fd;
		}
		failmsg("can't connect to manager", "addr=%s:%s", addr, ports);
	}

	template <typename addr_t>
	static int Connect(addr_t* addr, void* ip, int port)
	{
		auto* saddr = reinterpret_cast<sockaddr*>(addr);
		int fd = socket(saddr->sa_family, SOCK_STREAM, IPPROTO_TCP);
		if (fd == -1) {
			printf("failed to create socket for address family %d", saddr->sa_family);
			return -1;
		}
		char str[128] = {};
		inet_ntop(saddr->sa_family, ip, str, sizeof(str));
		int retcode = connect(fd, saddr, sizeof(*addr));
		while (retcode == -1 && errno == EINTR)
			retcode = ConnectWait(fd);

		if (retcode != 0) {
			printf("failed to connect to manager at %s:%d: %s\n", str, port, strerror(errno));
			close(fd);
			return -1;
		}
		return fd;
	}

	Connection(const Connection&) = delete;
	Connection& operator=(const Connection&) = delete;

	static int ConnectWait(int s)
	{
		struct pollfd pfd[1] = {{.fd = s, .events = POLLOUT}};
		int error = 0;
		socklen_t len = sizeof(error);

		if (poll(pfd, 1, -1) == -1)
			return -1;
		if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len) == -1)
			return -1;
		if (error != 0) {
			errno = error;
			return -1;
		}
		return 0;
	}
};

// Select is a wrapper around select system call.
class Select
{
public:
	Select()
	{
		FD_ZERO(&rdset_);
	}

	void Arm(int fd)
	{
		FD_SET(fd, &rdset_);
		max_fd_ = std::max(max_fd_, fd);
	}

	bool Ready(int fd) const
	{
		return FD_ISSET(fd, &rdset_);
	}

	void Wait(int ms)
	{
		timespec timeout = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000 * 1000};
		for (;;) {
			if (pselect(max_fd_ + 1, &rdset_, nullptr, nullptr, &timeout, nullptr) >= 0)
				break;

			if (errno != EINTR && errno != EAGAIN)
				fail("pselect failed");
		}
	}

	static void Prepare(int fd)
	{
		if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK))
			fail("fcntl(O_NONBLOCK) failed");
	}

private:
	fd_set rdset_;
	int max_fd_ = -1;

	Select(const Select&) = delete;
	Select& operator=(const Select&) = delete;
};
