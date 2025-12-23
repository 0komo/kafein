-module(kafein_ffi).
-export([wrap/2, unsafe_cast/1, strs_to_suites/1, send/2, shutdown/1, coerce_ssl_message/1]).

-type result(V, E) :: {ok, V} | {error, E}.

-type error() ::
    closed
    | nil
    | {options, any()}
    | ssl:error_alert()
    | {other, ssl:reason()}
    | {mug_error, inet:posix()}
    | {cipher_suite_not_recognized, string()}.

-spec wrap(inet:socket(), [ssl:tls_client_option()]) -> result(ssl:sslsocket(), error()).
wrap(Socket, Opts) ->
    coerce_result(
        ssl:connect(Socket, Opts)
    ).

-spec send(ssl:sslsocket(), binary()) -> result(nil, error()).
send(Socket, Data) ->
    normalise(
        ssl:send(Socket, Data)
    ).

-spec shutdown(ssl:sslsocket()) -> result(nil, error()).
shutdown(Socket) ->
    normalise(
        ssl:shutdown(Socket, read_write)
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
coerce_result({error, {options, _}} = E) ->
    E;
coerce_result({error, Other}) ->
    {error,
        case is_inet_error(Other) of
            true -> {tcp_error, Other};
            false -> {other, Other}
        end};
coerce_result(error) ->
    {error, nil};
coerce_result({ok, _} = V) ->
    V;
coerce_result(ok) ->
    {ok, nil}.

-spec normalise(result(V, any()) | ok | error) -> result(V, any()).
normalise(ok) ->
    {ok, nil};
normalise({ok, T}) ->
    {ok, T};
normalise({error, {timeout, _}}) ->
    {error, timeout};
normalise({error, _} = E) ->
    E.

-spec coerce_ssl_message(any()) -> any().
coerce_ssl_message({ssl, Socket, Data}) ->
    {packet, Socket, Data};
coerce_ssl_message({ssl_closed, Socket}) ->
    {socket_closed, Socket};
coerce_ssl_message({ssl_error, Socket, Error}) ->
    {ssl_error, Socket, coerce_result({error, Error})}.

-spec is_inet_error(atom()) -> boolean().
is_inet_error(Atom) ->
    <<C, _/utf8>> = atom_to_binary(Atom),
    C == ~"e" orelse C == ~"n".

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
