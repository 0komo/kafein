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

/// Curve that can be used for key exchange.
pub type Curve {
  X25519
  X448
  Secp521r1
  BrainpoolP512r1
  BrainpoolP384r1
  Secp384r1
  BrainpoolP256r1
  Secp256r1
  Sect571r1
  Sect571k1
  Sect409k1
  Sect409r1
  Sect283k1
  Sect283r1
  Secp256k1
  Sect239k1
  Sect233k1
  Sect233r1
  Secp224k1
  Secp224r1
  Sect193r1
  Sect193r2
  Secp192k1
  Secp192r1
  Sect163k1
  Sect163r1
  Sect163r2
  Secp160k1
  Secp160r1
  Secp160r2
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
  /// Conncetion timed out
  Timeout
  /// An opaque error meant for debugging
  Other(Dynamic)
  /// Error that comes from the connection
  PosixError(mug.Error)
  /// A specified cipher suite was not recognized
  CipherSuiteNotRecognized(name: String)
  /// Error that comes from the TLS interaction
  TlsAlert(kind: TlsAlertKind, description: String)
}

/// Error that can occur when exporting keying material(s).
pub type ExportKeyMaterialsError {
  ExporterMasterSecretAlreadyConsumed
  BadInput
}

/// Enum of supported protocol version.
pub type ProtocolVersion {
  Tlsv1
  Tlsv1m1
  Tlsv1m2
  Tlsv1m3
}

/// Enum of verification type.
pub type VerificationType {
  VerifyNone
  VerifyPeer
}

/// Record to describe a certificate.
pub type Certificate {
  Certificate(
    certfile: String,
    keyfile: String,
    password: Option(fn() -> String),
  )
}

/// Record to describe options when wrapping a TCP socket.
pub type WrapOptions {
  WrapOptions(
    protocol_versions: List(ProtocolVersion),
    alpn: List(String),
    cacert_file: Option(String),
    cipher_suites: List(String),
    depth: Int,
    verify: VerificationType,
    certificates: List(Certificate),
    curves: List(Curve),
    handshake_pause: Bool,
    server_name_indication: Option(String),
  )
}

/// Enum of message that comes from an SSL socket.
pub type SslMessage {
  Packet(SslSocket, BitArray)
  SocketClosed(SslSocket)
  SslError(SslSocket, Error)
}

/// Default options for wrapping.
pub const default_options = WrapOptions(
  protocol_versions: [Tlsv1m2, Tlsv1m3],
  alpn: [],
  cacert_file: None,
  cipher_suites: [],
  depth: 100,
  verify: VerifyPeer,
  certificates: [],
  curves: [],
  handshake_pause: False,
  server_name_indication: None,
)

/// Set protocol versions for upgrade.
pub fn protocol_versions(
  options: WrapOptions,
  versions protocol_versions: List(ProtocolVersion),
) -> WrapOptions {
  WrapOptions(..options, protocol_versions:)
}

/// Set supported ALPN protocols.
pub fn alpn(options: WrapOptions, protocols alpn: List(String)) -> WrapOptions {
  WrapOptions(..options, alpn:)
}

/// Set cacert file used for TLS.
pub fn cacert_file(
  options: WrapOptions,
  file cacert_file: String,
) -> WrapOptions {
  WrapOptions(..options, cacert_file: Some(cacert_file))
}

/// Set ciphers suites used for TLS.
pub fn cipher_suites(
  options: WrapOptions,
  ciphers cipher_suites: List(String),
) -> WrapOptions {
  WrapOptions(..options, cipher_suites:)
}

/// Set depth of allowed certificate chain.
pub fn depth(options: WrapOptions, depth depth: Int) -> WrapOptions {
  WrapOptions(..options, depth:)
}

/// Set verification type for certificate.
pub fn verify(
  options: WrapOptions,
  verify_type verify: VerificationType,
) -> WrapOptions {
  WrapOptions(..options, verify:)
}

/// Add certificate used for TLS.
pub fn certificate(
  options: WrapOptions,
  certificate cert: Certificate,
) -> WrapOptions {
  WrapOptions(
    ..options,
    certificates: list.append(options.certificates, [cert]),
  )
}

/// Add list of certificates used for TLS.
pub fn certificates(
  options: WrapOptions,
  certificates certs: List(Certificate),
) -> WrapOptions {
  WrapOptions(..options, certificates: list.append(options.certificates, certs))
}

/// Set curves used for TLS.
pub fn curves(options: WrapOptions, curves curves: List(Curve)) -> WrapOptions {
  WrapOptions(..options, curves:)
}

/// Make handshake pause after HELLO.
pub fn handshake_pause(options: WrapOptions) -> WrapOptions {
  WrapOptions(..options, handshake_pause: True)
}

/// Set SNI.
pub fn server_name_indication(
  options: WrapOptions,
  hostname name: String,
) -> WrapOptions {
  WrapOptions(..options, server_name_indication: Some(name))
}

/// Upgrades a TCP connection to SSL connection.
///
/// Returns an error if upgrading was failed.
pub fn wrap(
  optiohns options: WrapOptions,
  socket socket: mug.Socket,
) -> Result(SslSocket, Error) {
  use connect_options <- result.try(coerce_options(options))
  ffi_wrap(socket, connect_options)
}

/// Continue the handshake with specified wrap options.
///
/// Returns an error if handshake was failed.
pub fn handshake_continue(
  options options: WrapOptions,
  socket socket: SslSocket,
  timeout_miliseconds timeout: Int,
) -> Result(SslSocket, Error) {
  use handshake_options <- result.try(coerce_options(options))
  ssl_handshake_continue(socket, handshake_options, timeout)
}

/// Cancel the handshake operation.
///
/// Returns an error if cancellation was failed.
pub fn handshake_cancel(socket: SslSocket) -> Result(Nil, Error) {
  ffi_handshake_cancel(socket)
}

/// Export a single key material.
///
/// Returns an error if exporting was failed.
pub fn export_key_material(
  socket: SslSocket,
  label label: BitArray,
  context context: Option(BitArray),
  wanted_length length: Int,
) -> Result(BitArray, ExportKeyMaterialsError) {
  use key_materials <- result.try(
    export_key_materials(socket, [label], [context], [length]),
  )
  case list.first(key_materials) {
    Error(_) -> Error(BadInput)
    Ok(key_material) -> Ok(key_material)
  }
}

/// Export some of key materials.
///
/// Returns an error if exporting was failed.
pub fn export_key_materials(
  socket: SslSocket,
  labels labels: List(BitArray),
  contexts contexts: List(Option(BitArray)),
  wanted_lengths lengths: List(Int),
) -> Result(List(BitArray), ExportKeyMaterialsError) {
  let contexts =
    list.map(contexts, fn(wrap_context) {
      case wrap_context {
        Some(context) -> dynamic.bit_array(context)
        None -> atom.create("no_context") |> atom.to_dynamic
      }
    })

  ssl_export_key_materials(socket, labels, contexts, lengths)
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
  ssl_setopts(socket, [Active(Once)])
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

type InternalTlsOption {
  Versions(List(Atom))
  Cacerts(Dynamic)
  Depth(Int)
  Verify(VerificationType)
  Ciphers(List(Dynamic))
  AlpnAdvertisedProtocols(List(String))
  Cacertfile(String)
  CertsKeys(List(Dict(String, Dynamic)))
  Handshake(HandshakeType)
  Eccs(List(Curve))
  ServerNameIndication(Dynamic)
}

type GenTcpOption {
  Active(ActiveType)
}

type ActiveType {
  Once
}

type HandshakeType {
  Hello
  Full
}

fn coerce_options(
  options: WrapOptions,
) -> Result(List(InternalTlsOption), Error) {
  use ciphers <- result.try(strings_to_suites(options.cipher_suites))

  [
    Versions(
      list.map(options.protocol_versions, fn(ver) {
        atom.create(case ver {
          Tlsv1 -> "tlsv1"
          Tlsv1m1 -> "tlsv1.1"
          Tlsv1m2 -> "tlsv1.2"
          Tlsv1m3 -> "tlsv1.3"
        })
      }),
    ),
    Cacerts(public_key_cacerts_get()),
    Depth(options.depth),
    Verify(options.verify),
    CertsKeys(
      list.map(options.certificates, fn(cert) {
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
    Handshake(case options.handshake_pause {
      True -> Hello
      False -> Full
    }),
    ServerNameIndication(case options.server_name_indication {
      Some(name) -> binary_to_charlist(name)
      None -> atom.create("disable") |> atom.to_dynamic
    }),
  ]
  |> list.append(case options.cacert_file {
    Some(cacert_file) -> [Cacertfile(cacert_file)]
    None -> []
  })
  |> list.append(case ciphers {
    [] -> []
    _ -> [Ciphers(ciphers)]
  })
  |> list.append(case options.alpn {
    [] -> []
    alpn -> [AlpnAdvertisedProtocols(alpn)]
  })
  |> list.append(case options.curves {
    [] -> []
    eccs -> [Eccs(eccs)]
  })
  |> Ok
}

@external(erlang, "ssl", "export_key_materials")
fn ssl_export_key_materials(
  socket: SslSocket,
  labels: List(BitArray),
  contexts: List(Dynamic),
  wanted_lengths: List(Int),
) -> Result(List(BitArray), ExportKeyMaterialsError)

@external(erlang, "kafein_ffi", "handshake_cancel")
fn ffi_handshake_cancel(socket: SslSocket) -> Result(Nil, Error)

@external(erlang, "ssl", "handshake_continue")
fn ssl_handshake_continue(
  socket: SslSocket,
  options: List(InternalTlsOption),
  timeout: Int,
) -> Result(SslSocket, Error)

@external(erlang, "ssl", "recv")
fn ssl_recv(
  socket: SslSocket,
  n_bytes: Int,
  timeout: Int,
) -> Result(BitArray, mug.Error)

@external(erlang, "ssl", "setopts")
fn ssl_setopts(socket: SslSocket, options: List(GenTcpOption)) -> Dynamic

@external(erlang, "kafein_ffi", "wrap")
fn ffi_wrap(
  socket: mug.Socket,
  options: List(InternalTlsOption),
) -> Result(SslSocket, Error)

@external(erlang, "public_key", "cacerts_get")
fn public_key_cacerts_get() -> a

@external(erlang, "kafein_ffi", "coerce_ssl_message")
fn decode_ssl_message(msg: Dynamic) -> SslMessage

@external(erlang, "kafein_ffi", "strs_to_suites")
fn strings_to_suites(ciphers: List(String)) -> Result(List(Dynamic), Error)

@external(erlang, "erlang", "binary_to_list")
fn binary_to_charlist(value: String) -> Dynamic

@external(erlang, "kafein_ffi", "unsafe_cast")
fn unsafe_cast(value: a) -> b
