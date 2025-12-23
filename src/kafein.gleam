import gleam/bytes_tree.{type BytesTree}
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/erlang/atom.{type Atom}
import gleam/erlang/process
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import mug

/// An SSL Socket, upgraded form of TCP socket used for sending and receiving TCP messages.
pub type SslSocket

/// Error that might occur throughout the lifetime of the socket, see <https://www.erlang.org/doc/apps/ssl/ssl.html#t:tls_alert/0>.
pub type TlsAlertKind {
  CloseNotify
  UnexpectedMessage
  BadRecordMac
  RecordOverflow
  HandshakeFailure
  BadCertificate
  UnsupportedCertificate
  CertificateRevoked
  CertificateExpired
  CertificateUnknown
  IllegalParameter
  UnknownCa
  AccessDenied
  DecodeError
  DecryptError
  ExportRestriction
  ProtocolVersion
  InsufficientSecurity
  InternalError
  InappropriateFallback
  UserCanceled
  NoRenegotiation
  UnsupportedExtension
  CertificateUnobtainable
  UnrecognizedName
  BadCertificateStatusResponse
  BadCertificateHashValue
  UnknownPskIdentity
  NoApplicationProtocol
}

/// Error that can occur on some operation.
///
/// For more details, check out the Erlang docs:
///  - <https://www.erlang.org/doc/apps/ssl/ssl.html#connect/2>
///  - <https://www.erlang.org/doc/apps/ssl/ssl.html#str_to_suite/1>
///  - <https://www.erlang.org/doc/man/file#type-posix>
///  - <https://www.erlang.org/doc/man/inet#type-posix>
pub type Error {
  /// Connection was closed
  Closed
  /// An opaque error meant for debugging
  Options(Dynamic)
  /// An opaque error meant for debugging
  Other(Dynamic)
  /// Error that comes from the connection
  TcpError(mug.Error)
  /// A specified cipher suite was not recognized
  CipherSuiteNotRecognized(name: String)
  /// Error that comes from the TLS interaction
  TlsAlert(kind: TlsAlertKind, description: String)
}

/// Enum of supported protocol version
pub type ProtocolVersion {
  Tlsv1
  Tlsv1m1
  Tlsv1m2
  Tlsv1m3
}

/// Enum of verification type
pub type VerificationType {
  VerifyNone
  VerifyPeer
}

/// Record to describe a certificate
pub type Certificate {
  Certificate(
    certfile: String,
    keyfile: String,
    password: Option(fn() -> String),
  )
}

/// Record to describe options when wrapping a TCP socket
pub type WrapOptions {
  WrapOptions(
    protocol_versions: List(ProtocolVersion),
    alpn: List(String),
    cacertfile: Option(String),
    cipher_suites: List(String),
    depth: Int,
    verify: VerificationType,
    certificates: List(Certificate),
  )
}

/// Enum of message that comes from an SSL socket
pub type SslMessage {
  Packet(SslSocket, BitArray)
  SocketClosed(SslSocket)
  SslError(SslSocket, Error)
}

/// Default options when wrapping
pub fn default_options() -> WrapOptions {
  WrapOptions(
    protocol_versions: [Tlsv1m2, Tlsv1m3],
    alpn: [],
    cacertfile: None,
    cipher_suites: [],
    depth: 100,
    verify: VerifyPeer,
    certificates: [],
  )
}

/// Upgrades a TCP connection to SSL connection.
///
/// Returns an error if upgrading was failed.
pub fn wrap(
  socket: mug.Socket,
  options opts: WrapOptions,
) -> Result(SslSocket, Error) {
  use ciphers <- result.try(strings_to_suites(opts.cipher_suites))

  let connect_options =
    list.flatten([
      [
        Versions(
          list.map(opts.protocol_versions, fn(ver) {
            atom.create(case ver {
              Tlsv1 -> "tlsv1"
              Tlsv1m1 -> "tlsv1.1"
              Tlsv1m2 -> "tlsv1.2"
              Tlsv1m3 -> "tlsv1.3"
            })
          }),
        ),
        Cacerts(public_key_cacerts_get()),
        Depth(opts.depth),
        Verify(opts.verify),
        CertsKeys(
          list.map(opts.certificates, fn(cert) {
            dict.new()
            |> dict.insert("certfile", cert.certfile |> dynamic.string)
            |> dict.insert("keyfile", cert.keyfile |> dynamic.string)
            |> fn(d) {
              case cert.password {
                Some(func) -> d |> dict.insert("password", func |> unsafe_cast)
                None -> d
              }
            }
          }),
        ),
      ],
      optional(option.is_some(opts.cacertfile), fn() {
        let assert Some(path) = opts.cacertfile
        Cacertfile(path)
      }),
      optional(!list.is_empty(ciphers), fn() { Ciphers(ciphers) }),
      optional(!list.is_empty(opts.alpn), fn() {
        AlpnAdvertisedProtocols(opts.alpn)
      }),
    ])

  ffi_wrap(socket, connect_options)
}

pub fn send(socket: SslSocket, data: BitArray) -> Result(Nil, mug.Error) {
  send_builder(socket, bytes_tree.from_bit_array(data))
}

@external(erlang, "kafein_ffi", "send")
pub fn send_builder(
  socket: SslSocket,
  data: BytesTree,
) -> Result(Nil, mug.Error)

pub fn receive(
  socket: SslSocket,
  timeout_miliseconds timeout: Int,
) -> Result(BitArray, mug.Error) {
  ssl_recv(socket, 0, timeout)
}

pub fn receive_exact(
  socket: SslSocket,
  byte_size size: Int,
  timeout_miliseconds timeout: Int,
) -> Result(BitArray, mug.Error) {
  ssl_recv(socket, size, timeout)
}

pub fn receive_next_packet_as_message(socket: SslSocket) -> Nil {
  ssl_setopts(socket, [atom.create("once") |> Active])
  Nil
}

pub fn select_ssl_messages(
  selector: process.Selector(t),
  mapper: fn(SslMessage) -> t,
) -> process.Selector(t) {
  let ssl = atom.create("ssl")
  let closed = atom.create("ssl_closed")
  let error = atom.create("ssl_error")
  let map_message = fn(msg) { mapper(decode_ssl_message(msg)) }

  selector
  |> process.select_record(ssl, 2, map_message)
  |> process.select_record(closed, 1, map_message)
  |> process.select_record(error, 2, map_message)
}

@external(erlang, "kafein_ffi", "shutdown")
pub fn shutdown(socket: SslSocket) -> Result(Nil, mug.Error)

type ConnectOptions {
  Versions(List(Atom))
  Cacerts(Dynamic)
  Depth(Int)
  Verify(VerificationType)
  Ciphers(List(Dynamic))
  AlpnAdvertisedProtocols(List(String))
  Cacertfile(String)
  CertsKeys(List(Dict(String, Dynamic)))
}

type GenTcpOption {
  Active(Atom)
}

@external(erlang, "ssl", "recv")
fn ssl_recv(
  socket: SslSocket,
  n_bytes: Int,
  timeout: Int,
) -> Result(BitArray, mug.Error)

@external(erlang, "ssl", "setopts")
fn ssl_setopts(socket: SslSocket, options: List(GenTcpOption)) -> Dynamic

fn optional(cond: Bool, value: fn() -> a) -> List(a) {
  case cond {
    True -> [value()]
    False -> []
  }
}

@external(erlang, "kafein_ffi", "wrap")
fn ffi_wrap(
  socket: mug.Socket,
  options: List(ConnectOptions),
) -> Result(SslSocket, Error)

@external(erlang, "public_key", "cacerts_get")
fn public_key_cacerts_get() -> a

@external(erlang, "kafein_ffi", "coerce_ssl_message")
fn decode_ssl_message(msg: Dynamic) -> SslMessage

@external(erlang, "kafein_ffi", "strs_to_suites")
fn strings_to_suites(ciphers: List(String)) -> Result(List(Dynamic), Error)

@external(erlang, "kafein_ffi", "unsafe_cast")
pub fn unsafe_cast(value: a) -> b
