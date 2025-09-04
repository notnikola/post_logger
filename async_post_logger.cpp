// async_post_logger.cpp

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <iostream>
#include <sqlite3.h>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <csignal>

using namespace boost::asio;
using tcp = ip::tcp;
using boost::asio::awaitable;
using boost::asio::use_awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using namespace std::literals;

// ---- Config ----
static constexpr std::size_t MAX_BODY_BYTES = 10 * 1024 * 1024; // 10 MB safety cap

sqlite3* init_db(const std::string& path) {
    sqlite3* db;
    if (sqlite3_open(path.c_str(), &db)) {
        std::cerr << "Failed to open DB: " << sqlite3_errmsg(db) << std::endl;
        return nullptr;
    }

    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            headers TEXT,
            body TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )SQL";

    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::cerr << "SQL error: " << err << std::endl;
        sqlite3_free(err);
    }

    return db;
}

void log_post(sqlite3* db, const std::string& headers, const std::string& body) {
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO posts (headers, body) VALUES (?, ?)";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, headers.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, body.c_str(), -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            std::cerr << "sqlite3_step failed: " << sqlite3_errmsg(db) << std::endl;
        }
    } else {
        std::cerr << "sqlite3_prepare_v2 failed: " << sqlite3_errmsg(db) << std::endl;
    }
    sqlite3_finalize(stmt);
}

static inline std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

static inline std::string trim(std::string s) {
    auto not_space = [](unsigned char c){ return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

// Read exactly N bytes from socket into dst, appending to dst, enforcing MAX_BODY_BYTES
awaitable<void> read_exact_bytes(tcp::socket& socket, std::string& dst, std::size_t to_read) {
    if (to_read > MAX_BODY_BYTES) {
        co_return; // caller should send 413; we just bail
    }
    std::vector<char> buf(8192);
    std::size_t remaining = to_read;
    while (remaining > 0) {
        std::size_t chunk = std::min<std::size_t>(buf.size(), remaining);
        std::size_t n = co_await async_read(socket, buffer(buf.data(), chunk), use_awaitable);
        dst.append(buf.data(), n);
        remaining -= n;
    }
    co_return;
}

// Read a CRLF-terminated line into out (does not include CRLF)
awaitable<std::string> read_line(tcp::socket& socket, std::string& carry) {
    // If carry already has a full line, split it
    for (;;) {
        auto pos = carry.find("\r\n");
        if (pos != std::string::npos) {
            std::string line = carry.substr(0, pos);
            carry.erase(0, pos + 2);
            co_return line;
        }
        // else read more
        char buf[1024];
        std::size_t n = co_await socket.async_read_some(buffer(buf), use_awaitable);
        carry.append(buf, n);
    }
}

// Decode chunked body per RFC 7230 Section 4.1
awaitable<std::string> read_chunked_body(tcp::socket& socket, std::string& carry) {
    std::string out;
    for (;;) {
        std::string size_line = co_await read_line(socket, carry);
        // chunk-size may have extensions after ';'
        std::size_t semi = size_line.find(';');
        std::string hex_size = (semi == std::string::npos) ? size_line : size_line.substr(0, semi);
        std::size_t chunk_size = 0;
        try {
            chunk_size = std::stoul(trim(hex_size), nullptr, 16);
        } catch (...) {
            throw std::runtime_error("Invalid chunk size");
        }
        if (chunk_size == 0) {
            // Consume trailing header section after last-chunk (may be empty)
            // Read CRLF after 0-size (already consumed by read_line), then optional trailer headers ending with CRLF
            // We already consumed the CRLF after size line. Need to read a final CRLF after empty chunk.
            // Ensure carry has at least 2 bytes, otherwise read.
            while (carry.size() < 2) {
                char buf[512];
                std::size_t n = co_await socket.async_read_some(buffer(buf), use_awaitable);
                carry.append(buf, n);
            }
            if (carry.rfind("\r\n", carry.size()-2) == std::string::npos) {
                // If next is not CRLF, read and discard trailer headers until blank line
                // Simple approach: read lines until empty
                for (;;) {
                    std::string trailer = co_await read_line(socket, carry);
                    if (trailer.empty()) break;
                }
            } else {
                // Drop the immediate CRLF
                carry.erase(0, 2);
            }
            break;
        }
        // Ensure we have chunk_size bytes in carry; if not, read
        while (carry.size() < chunk_size + 2) { // +2 for CRLF after chunk
            char buf[4096];
            std::size_t n = co_await socket.async_read_some(buffer(buf), use_awaitable);
            carry.append(buf, n);
        }
        // Append chunk
        out.append(carry.data(), chunk_size);
        carry.erase(0, chunk_size);
        // Drop CRLF after chunk
        if (carry.substr(0,2) != "\r\n") throw std::runtime_error("Malformed chunk terminator");
        carry.erase(0,2);
        if (out.size() > MAX_BODY_BYTES) throw std::runtime_error("Body too large");
    }
    co_return out;
}

awaitable<void> handle_session(tcp::socket socket, sqlite3* db) {
    try {
        // 1) Read request line + headers
        std::string buffer_data;
        std::size_t header_end = co_await async_read_until(socket, dynamic_buffer(buffer_data), "\r\n\r\n", use_awaitable);
        std::string headers = buffer_data.substr(0, header_end);
        std::string carry = buffer_data.substr(header_end); // carries any bytes after the CRLFCRLF

        // 2) Parse headers for Content-Length / Transfer-Encoding
        std::istringstream hs(headers);
        std::string first_line;
        std::getline(hs, first_line); // request line
        std::string line;
        std::size_t content_length = 0;
        bool have_content_length = false;
        bool is_chunked = false;
        while (std::getline(hs, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            auto lower = to_lower(line);
            if (lower.starts_with("content-length:")) {
                auto val = trim(line.substr(15));
                try {
                    content_length = static_cast<std::size_t>(std::stoull(val));
                    have_content_length = true;
                } catch (...) {
                    // ignore invalid content length; treat as no length
                }
            } else if (lower.starts_with("transfer-encoding:")) {
                if (lower.find("chunked") != std::string::npos) {
                    is_chunked = true;
                }
            }
        }

        // 3) Read body per framing rules with safety cap
        std::string body;
        if (is_chunked) {
            // carry currently starts with "\r\n" from the header split; drop leading CRLF if present
            if (carry.rfind("\r\n", 0) == 0) carry.erase(0, 2);
            body = co_await read_chunked_body(socket, carry);
        } else if (have_content_length) {
            // We may already have some of the body in carry
            if (carry.size() >= content_length) {
                body.assign(carry.data(), content_length);
                carry.erase(0, content_length);
            } else {
                body = carry;
                std::size_t missing = content_length - body.size();
                // Enforce max size
                if (content_length > MAX_BODY_BYTES) {
                    // Send 413 and close
                    std::string resp =
                        "HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                    co_await async_write(socket, buffer(resp), use_awaitable);
                    boost::system::error_code ignore;
                    socket.shutdown(tcp::socket::shutdown_both, ignore);
                    co_return;
                }
                co_await read_exact_bytes(socket, body, missing);
            }
        } else {
            // No framing provided: read until EOF but guard with MAX_BODY_BYTES
            boost::system::error_code ec;
            body = carry;
            char temp[4096];
            while (body.size() < MAX_BODY_BYTES) {
                std::size_t n = co_await socket.async_read_some(buffer(temp), redirect_error(use_awaitable, ec));
                if (ec == error::eof || ec == error::connection_reset || n == 0) break;
                body.append(temp, n);
            }
        }

        // 4) Persist
        log_post(db, headers, body);

        // 5) Respond (close the connection to keep things simple)
        std::string response =
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "Content-Length: 2\r\n\r\nOK";
        co_await async_write(socket, buffer(response), use_awaitable);
        boost::system::error_code ignore;
        socket.shutdown(tcp::socket::shutdown_both, ignore);
    } catch (const std::exception& e) {
        std::cerr << "Session error: " << e.what() << "\n";
        // No suspension allowed here; do sync write and close.
        boost::system::error_code ignore;
        std::string resp =
            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        boost::asio::write(socket, buffer(resp), ignore);
        socket.shutdown(tcp::socket::shutdown_both, ignore);
    }
}

awaitable<void> listener(io_context& ctx, tcp::endpoint endpoint, sqlite3* db) {
    tcp::acceptor acceptor(ctx, endpoint);
    for (;;) {
        tcp::socket socket = co_await acceptor.async_accept(use_awaitable);
        co_spawn(ctx, handle_session(std::move(socket), db), detached);
    }
}

int main() {
    try {
        sqlite3* db = init_db("requests.db");
        if (!db) return 1;

        io_context ctx(1);
        signal_set signals(ctx, SIGINT, SIGTERM);
        signals.async_wait([&](auto, auto) {
            std::cout << "Shutting down...\n";
            sqlite3_close(db);
            ctx.stop();
        });

        co_spawn(ctx, listener(ctx, tcp::endpoint(tcp::v4(), 8080), db), detached);
        ctx.run();
    } catch (std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
    }

    return 0;
}
