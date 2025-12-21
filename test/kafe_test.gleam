import gleeunit
import kafe/tcp
import mug

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn kafe_test() {
  let assert Ok(socket) =
    mug.new("example.com", 443)
    |> mug.timeout(1000)
    |> mug.connect

  let assert Ok(ssl_socket) =
    socket
    |> tcp.wrap(tcp.SslOptions(..tcp.default_options()))

  echo ssl_socket
}
