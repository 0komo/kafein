# kafein

[![Package Version](https://img.shields.io/hexpm/v/kafein)](https://hex.pm/packages/kafein)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/kafein/)

A TLS client for Gleam on Erlang!

```sh
gleam add kafein@1
```
```gleam
import mug
import kafein.{WrapOptions}

pub fn main() {
  // Connect to a host
  let assert Ok(socket) =
    mug.new("protected-info.com", port: 443)
    |> mug.timeout(1000)
    |> mug.connect

  // Upgrade the connection to TLS
  let assert Ok(ssl_socket) = kafein.wrap(socket, options: kafein.default_options())

  // Send a data to the server
  let assert Ok(_) = kafein.send(ssl_socket, <<"Password: gleam-is-awesome\n":utf8>>)

  // Receive a data from the server
  let assert Ok(response) = kafein.receive(ssl_socket, 1000)

  echo response // -> <<"Here's the secret: gleam-is-awesome-too\n":utf8>>
}
```

Further documentation can be found at <https://hexdocs.pm/kafein>.

## Development

```sh
gleam run -m xtask/format # Format
gleam test # Run the tests
```
