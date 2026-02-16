import gleam/bit_array
import gleam/bytes_tree
import gleam/dynamic.{type Dynamic}
import gleam/erlang/application
import gleam/erlang/atom.{type Atom}
import gleam/erlang/process
import gleam/function
import gleam/option.{None}
import gleam/string
import gleeunit
import glisten
import kafein as kafe
import mug

const port = 64_793

pub fn main() -> Nil {
  logger_set_primary_config(
    atom.create("level"),
    atom.create("none") |> atom.to_dynamic,
  )
  start_server()
  gleeunit.main()
}

@external(erlang, "logger", "set_primary_config")
fn logger_set_primary_config(namespace: Atom, value: Dynamic) -> Dynamic

fn priv_directory() -> String {
  let assert Ok(path) = application.priv_directory("kafein")
  path
}

pub fn start_server() -> Nil {
  let assert Ok(_) =
    glisten.new(fn(_) { #(Nil, None) }, fn(state, msg, conn) {
      let assert glisten.Packet(msg) = msg
      let assert Ok(_) = glisten.send(conn, bytes_tree.from_bit_array(msg))
      glisten.continue(state)
    })
    |> glisten.with_tls(
      certfile: priv_directory() <> "/test_cert.pem",
      keyfile: priv_directory() <> "/test_key.pem",
    )
    |> glisten.start(port)
  Nil
}

fn connect() -> mug.Socket {
  let assert Ok(socket) =
    mug.new("localhost", port)
    |> mug.timeout(1000)
    |> mug.connect
    as "failed to connect to tcp socket"
  socket
}

pub fn bad_certificate_test() {
  let assert Error(kafe.TlsAlert(kafe.BadCertificate, _)) =
    kafe.default_options
    |> kafe.wrap(connect())
}

pub fn unknown_cipher_suite_test() {
  let assert Error(kafe.CipherSuiteNotRecognized("foo")) =
    kafe.default_options
    |> kafe.cipher_suites(["foo"])
    |> kafe.wrap(connect())
}

pub fn no_alpn_test() {
  let assert Error(kafe.TlsAlert(kafe.NoApplicationProtocol, _)) =
    kafe.default_options
    |> kafe.alpn(["foo"])
    |> kafe.wrap(connect())
}

pub fn failed_upgrade_tlsv1_only_test() {
  let assert Error(kafe.TlsAlert(kafe.ProtocolVersion, _)) =
    kafe.default_options
    |> kafe.protocol_versions([kafe.Tlsv1])
    |> kafe.wrap(connect())
}

pub fn upgrade_with_certificate_test() {
  let cert =
    kafe.Certificate(
      certfile: priv_directory() <> "/test_cert.pem",
      keyfile: priv_directory() <> "/test_key.pem",
      password: None,
    )

  let assert Ok(_) =
    kafe.default_options
    |> kafe.certificate(cert)
    |> kafe.verify(kafe.VerifyNone)
    |> kafe.depth(0)
    |> kafe.wrap(connect())
    as "failed to upgrade w/ certificate"
}

pub fn upgrade_with_handshake_pause_test() {
  let assert Ok(socket) =
    kafe.default_options
    |> kafe.handshake_pause
    |> kafe.wrap(connect())
    as "failed to upgrade half-way"

  let assert Ok(_) =
    kafe.default_options
    |> kafe.verify(kafe.VerifyNone)
    |> kafe.handshake_continue(socket, timeout_miliseconds: 100)
    as "failed to continue handshake"
}

pub fn upgrade_connection_test() {
  let assert Ok(socket) =
    kafe.default_options
    |> kafe.verify(kafe.VerifyNone)
    |> kafe.wrap(connect())
    as "failed to upgrade connection"

  socket
}

pub fn upgrade_connection_with_sni_test() {
  let assert Ok(socket) =
    kafe.default_options
    |> kafe.verify(kafe.VerifyNone)
    |> kafe.server_name_indication("localhost")
    |> kafe.wrap(connect())
    as "failed to upgrade connection with server_name_indication"

  socket
}

pub fn export_key_material_test() {
  let ssl_socket = upgrade_connection_test()

  let assert Ok(_) =
    kafe.export_key_material(ssl_socket, <<"my_label":utf8>>, None, 32)
    as "failed to export keying material"
}

pub fn simple_echo_test() {
  let ssl_socket = upgrade_connection_test()

  let assert Ok(_) = kafe.send(ssl_socket, <<"FOO DEEZ\n":utf8>>)
  let assert Ok(_) = kafe.send(ssl_socket, <<"BAR NUTS\n":utf8>>)
  let assert Ok(_) = kafe.send(ssl_socket, <<"erm akshually\n":utf8>>)
  let assert Ok(_) = kafe.send(ssl_socket, <<"actually not :(":utf8>>)

  // Wait a bit for all messages to be sent
  process.sleep(50)

  let assert Ok(data) = kafe.receive(ssl_socket, 100)
  let assert Ok(data) = bit_array.to_string(data)
  assert string.split(data, "\n")
    == ["FOO DEEZ", "BAR NUTS", "erm akshually", "actually not :("]

  let assert Ok(_) = kafe.shutdown(ssl_socket)
  assert kafe.send(ssl_socket, <<"here's another one!\n":utf8>>)
    == Error(mug.Closed)
  assert kafe.receive(ssl_socket, 100) == Error(mug.Closed)
}

pub fn simple_message_test() {
  let ssl_socket = upgrade_connection_test()
  kafe.receive_next_packet_as_message(ssl_socket)

  let assert Error(mug.Einval) = kafe.receive(ssl_socket, 0)

  let assert Ok(_) = kafe.send(ssl_socket, <<"foo, bar, and buzz":utf8>>)

  let selector =
    process.new_selector()
    |> kafe.select_ssl_messages(function.identity)

  let assert Ok(kafe.Packet(msg_ssl_socket, <<"foo, bar, and buzz":utf8>>)) =
    process.selector_receive(selector, 100)

  assert msg_ssl_socket == ssl_socket

  let assert Ok(_) = kafe.send(ssl_socket, <<"the mailman is not here":utf8>>)

  let assert Error(_) = process.selector_receive(selector, 100)

  assert Ok(<<"the mailman is not here":utf8>>) == kafe.receive(ssl_socket, 0)
}
