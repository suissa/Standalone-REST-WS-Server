#ifndef SIMPLE_WEB_SERVER_WS_HPP
#define SIMPLE_WEB_SERVER_WS_HPP

#include "asio_compatibility.hpp"
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace SimpleWeb {

namespace ws_detail {
inline std::string base64_encode(const uint8_t *data, std::size_t size) {
  static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((size + 2) / 3) * 4);
  for (std::size_t i = 0; i < size; i += 3) {
    const uint32_t a = data[i];
    const uint32_t b = i + 1 < size ? data[i + 1] : 0;
    const uint32_t c = i + 2 < size ? data[i + 2] : 0;
    const uint32_t n = (a << 16) | (b << 8) | c;
    out.push_back(table[(n >> 18) & 63]);
    out.push_back(table[(n >> 12) & 63]);
    out.push_back(i + 1 < size ? table[(n >> 6) & 63] : '=');
    out.push_back(i + 2 < size ? table[n & 63] : '=');
  }
  return out;
}

inline uint32_t rol(uint32_t value, unsigned bits) {
  return (value << bits) | (value >> (32 - bits));
}

inline std::array<uint8_t, 20> sha1(std::string_view input) {
  uint64_t bit_length = static_cast<uint64_t>(input.size()) * 8;
  std::vector<uint8_t> message(input.begin(), input.end());
  message.push_back(0x80);
  while ((message.size() % 64) != 56) message.push_back(0);
  for (int i = 7; i >= 0; --i) message.push_back(static_cast<uint8_t>(bit_length >> (i * 8)));

  uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
  for (std::size_t offset = 0; offset < message.size(); offset += 64) {
    uint32_t w[80]{};
    for (int i = 0; i < 16; ++i) {
      const std::size_t p = offset + static_cast<std::size_t>(i) * 4;
      w[i] = (static_cast<uint32_t>(message[p]) << 24) |
             (static_cast<uint32_t>(message[p + 1]) << 16) |
             (static_cast<uint32_t>(message[p + 2]) << 8) |
             static_cast<uint32_t>(message[p + 3]);
    }
    for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; ++i) {
      uint32_t f, k;
      if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6; }
      const uint32_t temp = rol(a, 5) + f + e + k + w[i];
      e = d; d = c; c = rol(b, 30); b = a; a = temp;
    }
    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
  }

  std::array<uint8_t, 20> digest{};
  const uint32_t h[5] = {h0, h1, h2, h3, h4};
  for (int i = 0; i < 5; ++i)
    for (int j = 0; j < 4; ++j)
      digest[static_cast<std::size_t>(i) * 4 + j] = static_cast<uint8_t>(h[i] >> (24 - j * 8));
  return digest;
}

inline std::string websocket_accept(std::string_view key) {
  const auto digest = sha1(std::string(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  return base64_encode(digest.data(), digest.size());
}

inline bool has_token(std::string_view value, std::string_view token) {
  std::size_t start = 0;
  while (start < value.size()) {
    const auto comma = value.find(',', start);
    const auto end = comma == std::string_view::npos ? value.size() : comma;
    auto part = value.substr(start, end - start);
    while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) part.remove_prefix(1);
    while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) part.remove_suffix(1);
    if (part == token) return true;
    if (comma == std::string_view::npos) break;
    start = comma + 1;
  }
  return false;
}
} // namespace ws_detail

template <typename Socket = asio::ip::tcp::socket>
class WebSocketServer {
public:
  class Connection;
  using connection_ptr = std::shared_ptr<Connection>;
  using message_handler = std::function<void(const connection_ptr &, uint8_t, std::string_view)>;

  explicit WebSocketServer(uint16_t port = 8081, std::size_t max_message_size = 16 * 1024 * 1024)
      : context_(), acceptor_(context_), port_(port), max_message_size_(max_message_size) {}

  ~WebSocketServer() { stop(); }

  WebSocketServer(const WebSocketServer &) = delete;
  WebSocketServer &operator=(const WebSocketServer &) = delete;

  void on_message(message_handler handler) { handler_ = std::move(handler); }

  void start() {
    if (running_.exchange(true)) return;
    asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v4(), port_);
    error_code ec;
    acceptor_.open(endpoint.protocol(), ec);
    if (ec) { running_ = false; throw system_error(ec); }
    acceptor_.set_option(asio::socket_base::reuse_address(true), ec);
    if (ec) { running_ = false; throw system_error(ec); }
    acceptor_.bind(endpoint, ec);
    if (ec) { running_ = false; throw system_error(ec); }
    acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) { running_ = false; throw system_error(ec); }
    port_ = acceptor_.local_endpoint().port();
    accept_thread_ = std::thread([this] { accept_loop(); });
  }

  void stop() noexcept {
    if (!running_.exchange(false)) return;
    error_code ec;
    acceptor_.close(ec);
    if (accept_thread_.joinable()) accept_thread_.join();
  }

  uint16_t port() const noexcept { return port_; }
  bool running() const noexcept { return running_.load(); }

private:
  void accept_loop() {
    while (running_) {
      auto socket = std::make_shared<Socket>(context_);
      error_code ec;
      acceptor_.accept(*socket, ec);
      if (ec) {
        if (running_) continue;
        break;
      }
      std::thread([this, socket] { handle_connection(std::move(socket)); }).detach();
    }
  }

  static std::string read_http_request(Socket &socket) {
    asio::streambuf buffer;
    error_code ec;
    asio::read_until(socket, buffer, "\r\n\r\n", ec);
    if (ec) throw system_error(ec);
    return std::string(asio::buffers_begin(buffer.data()), asio::buffers_end(buffer.data()));
  }

  static std::string header_value(const std::string &request, const std::string &name) {
    std::size_t pos = request.find("\r\n");
    while (pos != std::string::npos) {
      const std::size_t line_start = pos + 2;
      const std::size_t line_end = request.find("\r\n", line_start);
      if (line_end == std::string::npos) break;
      const auto line = std::string_view(request).substr(line_start, line_end - line_start);
      const auto colon = line.find(':');
      if (colon != std::string_view::npos) {
        auto key = line.substr(0, colon);
        if (key.size() == name.size()) {
          bool equal = true;
          for (std::size_t i = 0; i < key.size(); ++i)
            if (std::tolower(static_cast<unsigned char>(key[i])) != std::tolower(static_cast<unsigned char>(name[i]))) equal = false;
          if (equal) {
            auto value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
            return std::string(value);
          }
        }
      }
      pos = line_end;
    }
    return {};
  }

  void handshake(Socket &socket) {
    const auto request = read_http_request(socket);
    const auto first_line_end = request.find("\r\n");
    if (first_line_end == std::string::npos || request.compare(0, 3, "GET") != 0)
      throw std::runtime_error("invalid WebSocket upgrade request");

    const auto upgrade = header_value(request, "Upgrade");
    const auto connection = header_value(request, "Connection");
    const auto version = header_value(request, "Sec-WebSocket-Version");
    const auto key = header_value(request, "Sec-WebSocket-Key");
    if (upgrade.empty() || connection.empty() || version != "13" || key.empty() || !ws_detail::has_token(upgrade, "websocket") || !ws_detail::has_token(connection, "Upgrade"))
      throw std::runtime_error("invalid WebSocket headers");

    const std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + ws_detail::websocket_accept(key) + "\r\n\r\n";
    asio::write(socket, asio::buffer(response));
  }

  static void send_frame(Socket &socket, uint8_t opcode, std::string_view payload) {
    std::vector<uint8_t> frame;
    frame.reserve(payload.size() + 10);
    frame.push_back(static_cast<uint8_t>(0x80 | (opcode & 0x0f)));
    if (payload.size() < 126) {
      frame.push_back(static_cast<uint8_t>(payload.size()));
    } else if (payload.size() <= 0xffff) {
      frame.push_back(126);
      frame.push_back(static_cast<uint8_t>(payload.size() >> 8));
      frame.push_back(static_cast<uint8_t>(payload.size()));
    } else {
      frame.push_back(127);
      const uint64_t length = payload.size();
      for (int i = 7; i >= 0; --i) frame.push_back(static_cast<uint8_t>(length >> (i * 8)));
    }
    frame.insert(frame.end(), payload.begin(), payload.end());
    asio::write(socket, asio::buffer(frame));
  }

  static std::pair<uint8_t, std::string> read_frame(Socket &socket, std::size_t max_size) {
    std::array<uint8_t, 2> header{};
    asio::read(socket, asio::buffer(header));
    const bool fin = (header[0] & 0x80) != 0;
    const uint8_t opcode = header[0] & 0x0f;
    const bool masked = (header[1] & 0x80) != 0;
    uint64_t length = header[1] & 0x7f;
    if (!fin) throw std::runtime_error("fragmented WebSocket frames are not supported");
    if (length == 126) {
      std::array<uint8_t, 2> ext{}; asio::read(socket, asio::buffer(ext));
      length = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
    } else if (length == 127) {
      std::array<uint8_t, 8> ext{}; asio::read(socket, asio::buffer(ext));
      length = 0; for (auto byte : ext) length = (length << 8) | byte;
      if (length >> 63) throw std::runtime_error("invalid WebSocket payload length");
    }
    if (!masked || length > max_size) throw std::runtime_error("invalid WebSocket frame");
    if ((opcode & 0x08) && length > 125) throw std::runtime_error("invalid control frame");

    std::array<uint8_t, 4> mask{}; asio::read(socket, asio::buffer(mask));
    std::string payload(static_cast<std::size_t>(length), '\0');
    if (length) asio::read(socket, asio::buffer(payload));
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]);
    return {opcode, std::move(payload)};
  }

  void handle_connection(std::shared_ptr<Socket> socket) {
    try {
      handshake(*socket);
      auto connection = std::make_shared<Connection>(std::move(socket));
      while (running_) {
        auto [opcode, payload] = read_frame(connection->socket(), max_message_size_);
        if (opcode == 0x8) { connection->close(); break; }
        if (opcode == 0x9) { connection->send(0xA, payload); continue; }
        if (opcode == 0xA) continue;
        if (opcode != 0x1 && opcode != 0x2) throw std::runtime_error("unsupported WebSocket opcode");
        if (handler_) handler_(connection, opcode, payload);
        else connection->send(opcode, payload);
      }
    } catch (...) {
      error_code ignored;
      socket->close(ignored);
    }
  }

  class ConnectionImpl;

public:
  class Connection : public std::enable_shared_from_this<Connection> {
  public:
    explicit Connection(std::shared_ptr<Socket> socket) : socket_(std::move(socket)) {}
    Socket &socket() { return *socket_; }
    void send(uint8_t opcode, std::string_view payload) {
      std::lock_guard<std::mutex> lock(write_mutex_);
      send_frame(*socket_, opcode, payload);
    }
    void send_text(std::string_view payload) { send(0x1, payload); }
    void send_binary(std::string_view payload) { send(0x2, payload); }
    void ping(std::string_view payload = {}) { send(0x9, payload); }
    void close() {
      std::lock_guard<std::mutex> lock(write_mutex_);
      error_code ignored;
      if (socket_->is_open()) {
        send_frame(*socket_, 0x8, {});
        socket_->shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
        socket_->close(ignored);
      }
    }
  private:
    std::shared_ptr<Socket> socket_;
    std::mutex write_mutex_;
  };

private:
  io_context context_;
  asio::ip::tcp::acceptor acceptor_;
  uint16_t port_;
  std::size_t max_message_size_;
  std::atomic<bool> running_{false};
  std::thread accept_thread_;
  message_handler handler_;
};

} // namespace SimpleWeb

#endif
