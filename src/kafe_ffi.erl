-module(kafe_ffi).
-export([wrap/2]).

-type result(V, E) :: {ok, V} | {error, E}.

-type option(V) :: {some, V} | none.

-type protocol_version() :: tlsv1 | tlsv1m1 | tlsv1m2 | tlsv1m3.

%% erlfmt:ignore
-type ssl_options() ::
    {ssl_options,
        ProtocolVersions :: [protocol_version()],
        Alpn :: [binary()],
        Cafile :: option(binary()),
        ChiperSuites :: [binary()],
        Depth :: pos_integer(),
        Verify :: verify_none | verify_peer}.

-type wrap_error() ::
    closed | {options, any()} | ssl:error_alert() | ssl:reason() | {cipher_suite_not_recognized, string()}.

-spec wrap(inet:socket(), ssl_options()) -> result(ssl:sslsocket(), wrap_error()).
wrap(Socket, {ssl_options, ProtocolVersions, Alpn, Cafile, ChiperSuiteNames, Depth, Verify}) ->
    Res = maybe
        {ok, Ciphers} ?= strs_to_suites(ChiperSuiteNames),
        ssl:connect(
            Socket,
            %% eqwalizer:ignore not sure why it yells here
            lists:append([
                [
                    {versions, lists:map(fun normalise/1, ProtocolVersions)},
                    {alpn_advertised_protocols, Alpn},
                    {cacerts, public_key:cacerts_get()},
                    {ciphers, Ciphers},
                    {depth, Depth},
                    {verify, Verify}
                ],
                optional(
                    is_some(Cafile),
                    %% eqwalizer:ignore unwrap_option will always unwrap cuz of is_some
                    fun() -> {cacertfile, unicode:characters_to_list(unwrap_option(Cafile))} end
                )
            ])
        )
    end,
    normalise(Res).

-spec normalise
    (tlsv1 | tlsv1m1 | tlsv1m2 | tlsv1m3) -> ssl:protocol_version();
    (result(V, E)) -> result(V, E);
    ({error, {not_recognized, string()}}) -> {error, {cipher_suite_not_recognized, string()}}.
%% Protocol version
normalise(tlsv1) -> tlsv1;
normalise(tlsv1m1) -> 'tlsv1.1';
normalise(tlsv1m2) -> 'tlsv1.2';
normalise(tlsv1m3) -> 'tlsv1.3';
normalise({error, {not_recognized, Name}}) -> {error, {cipher_suite_not_recognized, list_to_binary(Name)}};
normalise({error, {tls_alert, {Name, Desc}}}) -> {error, {tls_alert, {Name, list_to_binary(Desc)}}};
normalise({ok, _} = V) -> V;
normalise({error, _} = E) -> E.

-spec strs_to_suites([binary()]) -> result(ssl:ciphers(), {cipher_suite_not_recognized, binary()}).
strs_to_suites(Names) ->
    Unchecked = lists:map(
        fun(V) ->
            %% eqwalizer:ignore will always return string()
            ssl:str_to_suite(unicode:characters_to_list(V))
        end,
        Names
    ),
    case lists:search(fun is_error/1, Unchecked) of
        {value, {error, _} = E} -> normalise(E);
        %% eqwalizer:ignore it's already handled by the lists:search
        false -> {ok, Unchecked}
    end.

-spec optional(boolean(), fun(() -> T)) -> [T] | [].
optional(Pred, V) ->
    case Pred of
        true -> [V()];
        false -> []
    end.

-spec unwrap_option(option(T)) -> T | none.
unwrap_option({some, V}) -> V;
unwrap_option(none) -> none.

-spec is_some(option(any())) -> boolean().
is_some({some, _}) -> true;
is_some(none) -> false.

-spec is_error(result(any(), any()) | any()) -> boolean().
is_error({error, _}) -> true;
is_error(_) -> false.
