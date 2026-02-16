-module(kafein_ffi).
-export([
    wrap/2,
    unsafe_cast/1,
    strs_to_suites/1,
    send/2,
    shutdown/1,
    coerce_ssl_message/1,
    handshake_cancel/1
]).

-type result(V, E) :: {ok, V} | {error, E}.

-type error() ::
    closed
    | nil
    | {tls_alert}
    | {other, ssl:reason()}
    | {posix_error, inet:posix()}
    | {cipher_suite_not_recognized, string()}.

-spec wrap(inet:socket(), [ssl:tls_client_option()]) -> result(ssl:sslsocket(), error()).

wrap(Socket, Opts) ->
    coerce_result(
        ssl:connect(Socket, Opts)
    ).

-spec send(ssl:sslsocket(), binary()) -> result(nil, error()).

send(Socket, Data) ->
    coerce_result(
        ssl:send(Socket, Data)
    ).

-spec shutdown(ssl:sslsocket()) -> result(nil, error()).

shutdown(Socket) ->
    coerce_result(
        ssl:shutdown(Socket, read_write)
    ).

-spec handshake_cancel(ssl:socket()) -> result(nil, error()).

handshake_cancel(Socket) ->
    coerce_result(
        ssl:handshake_cancel(Socket)
    ).

-spec unsafe_cast(any()) -> any().

unsafe_cast(V) -> V.

-spec coerce_result(result(V, any()) | ok | error) -> result(V, error()).

coerce_result({error, {not_recognized, Name}}) ->
    {error, {cipher_suite_not_recognized, list_to_binary(Name)}};
coerce_result({error, {tls_alert, {Kind, Desc}}}) ->
    {error, {tls_alert, Kind, list_to_binary(Desc)}};
coerce_result({error, closed} = E) ->
    E;
coerce_result({error, timeout} = E) ->
    E;
coerce_result({error, Other}) ->
    {error,
        case is_inet_error(Other) of
            true -> {posix_error, Other};
            false -> {other, Other}
        end};
coerce_result({ok, _} = V) ->
    V;
coerce_result({ok, V, _}) ->
    {ok, V};
coerce_result(Result) when is_atom(Result) ->
    case Result of
        ok -> {ok, nil};
        error -> {error, nil}
    end.

-spec coerce_ssl_message
    ({ssl, ssl:sslsocket(), binary()}) -> {packet, ssl:sslsocket(), binary()};
    ({ssl_closed, ssl:sslsocket()}) -> {socket_closed, ssl:sslsocket()};
    ({ssl_error, ssl:sslsocket(), any()}) -> {ssl_error, ssl:sslsocket(), any()}.

coerce_ssl_message({ssl, Socket, Data}) ->
    {packet, Socket, Data};
coerce_ssl_message({ssl_closed, Socket}) ->
    {socket_closed, Socket};
coerce_ssl_message({ssl_error, Socket, Error}) ->
    {ssl_error, Socket, coerce_result({error, Error})}.

-spec is_inet_error(any()) -> boolean().

is_inet_error(Atom) when is_atom(Atom) ->
    <<C, _/utf8>> = atom_to_binary(Atom),
    C == ~"e" orelse C == ~"n";
is_inet_error(_) ->
    false.

-spec strs_to_suites([binary()]) -> result(ssl:ciphers(), {cipher_suite_not_recognized, binary()}).

strs_to_suites(Names) ->
    Unchecked = lists:map(
        fun(V) ->
            %% eqwalizer:ignore -- will always return string()
            ssl:str_to_suite(binary_to_list(V))
        end,
        Names
    ),
    case lists:search(fun is_error/1, Unchecked) of
        {value, {error, _} = E} -> coerce_result(E);
        %% eqwalizer:ignore -- it's already handled by the lists:search
        false -> {ok, Unchecked}
    end.

-spec is_error(result(any(), any()) | any()) -> boolean().

is_error({error, _}) -> true;
is_error(_) -> false.
