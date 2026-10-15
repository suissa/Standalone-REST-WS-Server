#include <server_http.hpp>
#include <server_ws.hpp>
#include <iostream>
#include <thread>

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
using WsServer = SimpleWeb::WebSocketServer<>;

int main() {
  HttpServer http;
  http.config.port = 8080;
  http.resource["^/hello$"]["GET"] =
      [](std::shared_ptr<HttpServer::Response> response,
         std::shared_ptr<HttpServer::Request> /*request*/) {
        response->write("Hello from HTTP");
      };

  WsServer websocket(8081);
  websocket.on_message([](const WsServer::connection_ptr &connection,
                          uint8_t opcode, std::string_view payload) {
    connection->send(opcode, payload);
  });
  websocket.start();

  std::cout << "WebSocket listening on ws://127.0.0.1:" << websocket.port() << std::endl;
  std::cout << "HTTP listening on http://127.0.0.1:8080/hello" << std::endl;

  http.start();
  return 0;
}
