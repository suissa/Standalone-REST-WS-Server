#include "server_ws.hpp"
#include <cassert>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using asio::ip::tcp;

static void write_masked_frame(tcp::socket &socket, uint8_t opcode, const std::string &payload) {
  std::vector<uint8_t> frame;
  frame.push_back(static_cast<uint8_t>(0x80 | opcode));
  if (payload.size() < 126) {
    frame.push_back(static_cast<uint8_t>(0x80 | payload.size()));
  } else {
    assert(payload.size() <= 0xffff);
    frame.push_back(0x80 | 126);
    frame.push_back(static_cast<uint8_t>(payload.size() >> 8));
    frame.push_back(static_cast<uint8_t>(payload.size()));
  }
  const uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
  frame.insert(frame.end(), std::begin(mask), std::end(mask));
  for (std::size_t i = 0; i < payload.size(); ++i)
    frame.push_back(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]);
  asio::write(socket, asio::buffer(frame));
}

static std::string read_server_frame(tcp::socket &socket, uint8_t expected_opcode) {
  uint8_t header[2];
  asio::read(socket, asio::buffer(header));
  assert((header[0] & 0x80) != 0);
  assert((header[0] & 0x0f) == expected_opcode);
  assert((header[1] & 0x80) == 0);
  uint64_t length = header[1] & 0x7f;
  if (length == 126) {
    uint8_t ext[2]; asio::read(socket, asio::buffer(ext));
    length = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
  }
  std::string payload(static_cast<std::size_t>(length), '\0');
  if (length) asio::read(socket, asio::buffer(payload));
  return payload;
}

static void run_client(uint16_t port, int id) {
  asio::io_context io;
  tcp::socket socket(io);
  socket.connect(tcp::endpoint(asio::ip::address_v4::loopback(), port));

  const std::string key = "dGhlIHNhbXBsZSBub25jZQ==";
  const std::string request =
      "GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
      "Connection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\n"
      "Sec-WebSocket-Version: 13\r\n\r\n";
  asio::write(socket, asio::buffer(request));

  asio::streambuf response;
  asio::read_until(socket, response, "\r\n\r\n");
  const std::string response_text(asio::buffers_begin(response.data()), asio::buffers_end(response.data()));
  assert(response_text.find("101 Switching Protocols") != std::string::npos);
  assert(response_text.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != std::string::npos);

  const std::string message = "hello-from-client-" + std::to_string(id);
  write_masked_frame(socket, 0x1, message);
  assert(read_server_frame(socket, 0x1) == message);

  write_masked_frame(socket, 0x9, "ping");
  assert(read_server_frame(socket, 0xA) == "ping");

  write_masked_frame(socket, 0x8, "");
  socket.close();
}

int main() {
  SimpleWeb::WebSocketServer<> server(0);
  server.start();
  assert(server.running());
  assert(server.port() != 0);

  std::vector<std::thread> clients;
  for (int i = 0; i < 8; ++i) clients.emplace_back(run_client, server.port(), i);
  for (auto &client : clients) client.join();

  server.stop();
  std::cout << "WebSocket communication tests passed\n";
  return 0;
}
