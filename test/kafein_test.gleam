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
import kafein
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

fn start_server() -> Nil {
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
  socket
}

pub fn bad_certificate_test() {
  let assert Error(kafein.TlsAlert(kafein.BadCertificate, _)) =
    connect() |> kafein.wrap(kafein.default_options())
}

pub fn unknown_cipher_suite_test() {
  let assert Error(kafein.CipherSuiteNotRecognized(_)) =
    connect()
    |> kafein.wrap(
      kafein.WrapOptions(..kafein.default_options(), cipher_suites: ["foo"]),
    )
}

pub fn no_alpn_test() {
  let assert Error(kafein.TlsAlert(kafein.NoApplicationProtocol, _)) =
    connect()
    |> kafein.wrap(kafein.WrapOptions(..kafein.default_options(), alpn: ["foo"]))
}

pub fn failed_upgrade_tlsv1_only_test() {
  let assert Error(kafein.TlsAlert(kafein.ProtocolVersion, _)) =
    connect()
    |> kafein.wrap(
      kafein.WrapOptions(..kafein.default_options(), protocol_versions: [kafein.Tlsv1]),
    )
}

pub fn upgrade_with_certificate_test() {
  let cert =
    kafein.Certificate(
      certfile: priv_directory() <> "/test_cert.pem",
      keyfile: priv_directory() <> "/test_key.pem",
      password: None,
    )

  let assert Ok(_) =
    connect()
    |> kafein.wrap(
      kafein.WrapOptions(
        ..kafein.default_options(),
        certificates: [cert],
        verify: kafein.VerifyNone,
        depth: 0,
      ),
    )
}

pub fn upgrade_connection_test() {
  let assert Ok(_) =
    connect()
    |> kafein.wrap(
      kafein.WrapOptions(..kafein.default_options(), verify: kafein.VerifyNone),
    )
}

pub fn simple_echo_test() {
  let assert Ok(ssl_socket) =
    connect()
    |> kafein.wrap(
      kafein.WrapOptions(..kafein.default_options(), verify: kafein.VerifyNone),
    )

  let assert Ok(_) = kafein.send(ssl_socket, <<"FOO DEEZ\n":utf8>>)
  let assert Ok(_) = kafein.send(ssl_socket, <<"BAR NUTS\n":utf8>>)
  let assert Ok(_) = kafein.send(ssl_socket, <<"erm akshually\n":utf8>>)
  let assert Ok(_) = kafein.send(ssl_socket, <<"actually not :(":utf8>>)

  // Wait a bit for all messages to be sent
  process.sleep(50)

  let assert Ok(data) = kafein.receive(ssl_socket, 100)
  let assert Ok(data) = bit_array.to_string(data)
  assert string.split(data, "\n")
    == ["FOO DEEZ", "BAR NUTS", "erm akshually", "actually not :("]

  let assert Ok(_) = kafein.shutdown(ssl_socket)

  let assert Error(_) =
    kafein.send(ssl_socket, <<"may i send you one more kind gentleman?":utf8>>)
  let assert Error(_) = kafein.receive(ssl_socket, 100)
}

pub fn simple_message_test() {
  let assert Ok(ssl_socket) =
    connect()
    |> kafein.wrap(
      kafein.WrapOptions(..kafein.default_options(), verify: kafein.VerifyNone),
    )
  kafein.receive_next_packet_as_message(ssl_socket)

  let assert Error(mug.Einval) = kafein.receive(ssl_socket, 0)

  let assert Ok(_) = kafein.send(ssl_socket, <<"foo, bar, and buzz":utf8>>)

  let selector =
    process.new_selector()
    |> kafein.select_ssl_messages(function.identity)

  let assert Ok(kafein.Packet(msg_ssl_socket, <<"foo, bar, and buzz":utf8>>)) =
    process.selector_receive(selector, 100)

  assert msg_ssl_socket == ssl_socket

  let assert Ok(_) = kafein.send(ssl_socket, <<"the mailman is not here":utf8>>)

  let assert Error(_) = process.selector_receive(selector, 100)

  assert Ok(<<"the mailman is not here":utf8>>) == kafein.receive(ssl_socket, 0)
}
