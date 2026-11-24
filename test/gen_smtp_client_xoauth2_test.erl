-module(gen_smtp_client_xoauth2_test).
-include_lib("eunit/include/eunit.hrl").

%% A tiny scripted SMTP server that behaves like Exchange Online:
%% advertises "AUTH LOGIN XOAUTH2" and, for a bad token, answers with a 334 challenge
%% containing a base64 JSON error that the client must acknowledge with an empty line.

-define(GOOD_TOKEN, "good-token").

xoauth2_success_test() ->
    {Port, Server} = start_server(),
    {ok, Sock} = gen_smtp_client:open(opts(Port, ?GOOD_TOKEN)),
    gen_smtp_client:close(Sock),
    Cmds = stop_server(Server),
    ?assertEqual([], [C || "AUTH LOGIN" ++ _ = C <- Cmds]),
    ?assertMatch([_], [C || "AUTH XOAUTH2 " ++ _ = C <- Cmds]).

xoauth2_failure_reports_reason_test() ->
    {Port, Server} = start_server(),
    Res = gen_smtp_client:open(opts(Port, "bad-token")),
    Cmds = stop_server(Server),
    ?assertMatch(
        {error, no_more_hosts,
            {permanent_failure, _, {auth_failed, <<"{\"status\":\"401\"", _/binary>>}}},
        Res
    ),
    %% server must have seen the empty acknowledgement line before the connection was closed
    ?assert(lists:member("", Cmds)),
    %% forced mechanism: no LOGIN/PLAIN attempts with the token
    ?assertEqual([], [C || "AUTH LOGIN" ++ _ = C <- Cmds]).

mechanism_list_is_a_priority_order_test() ->
    %% server advertises LOGIN and XOAUTH2; the list decides which is tried first
    {Port1, Server1} = start_server(),
    Opts1 = lists:keystore(auth_mechanism, 1, opts(Port1, ?GOOD_TOKEN), {auth_mechanism, [xoauth2, login]}),
    {ok, Sock1} = gen_smtp_client:open(Opts1),
    gen_smtp_client:close(Sock1),
    Cmds1 = stop_server(Server1),
    ?assertEqual([], [C || "AUTH LOGIN" ++ _ = C <- Cmds1]),

    {Port2, Server2} = start_server(),
    Opts2 = lists:keystore(auth_mechanism, 1, opts(Port2, ?GOOD_TOKEN), {auth_mechanism, [login, xoauth2]}),
    {ok, Sock2} = gen_smtp_client:open(Opts2),
    gen_smtp_client:close(Sock2),
    Cmds2 = stop_server(Server2),
    ?assertMatch([_], [C || "AUTH LOGIN" ++ _ = C <- Cmds2]),
    ?assertMatch([_], [C || "AUTH XOAUTH2 " ++ _ = C <- Cmds2]).

mechanism_list_acts_as_allowlist_test() ->
    %% PLAIN is not advertised and XOAUTH2 is not allowed: nothing to try
    {Port, Server} = start_server(),
    Opts = lists:keystore(auth_mechanism, 1, opts(Port, ?GOOD_TOKEN), {auth_mechanism, [plain, cram_md5]}),
    Res = gen_smtp_client:open(Opts),
    Cmds = stop_server(Server),
    ?assertMatch({error, no_more_hosts, {permanent_failure, _, auth_failed}}, Res),
    ?assertEqual([], [C || "AUTH " ++ _ = C <- Cmds]).

without_mechanism_option_tries_other_mechanisms_first_test() ->
    {Port, Server} = start_server(),
    Opts = proplists:delete(auth_mechanism, opts(Port, ?GOOD_TOKEN)),
    {ok, Sock} = gen_smtp_client:open(Opts),
    gen_smtp_client:close(Sock),
    Cmds = stop_server(Server),
    %% default behaviour is unchanged: LOGIN is attempted before XOAUTH2
    ?assertMatch([_ | _], [C || "AUTH LOGIN" ++ _ = C <- Cmds]).

opts(Port, Token) ->
    [
        {relay, "127.0.0.1"},
        {port, Port},
        {no_mx_lookups, true},
        {tls, never},
        {auth, always},
        {auth_mechanism, xoauth2},
        {username, "user@example.com"},
        {password, Token},
        {hostname, "localhost"}
    ].

start_server() ->
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}, {packet, line}]),
    {ok, Port} = inet:port(L),
    Parent = self(),
    Pid = spawn_link(fun() ->
        {ok, S} = gen_tcp:accept(L, 5000),
        send(S, "220 mock ESMTP\r\n"),
        Cmds = loop(S, []),
        Parent ! {cmds, self(), lists:reverse(Cmds)}
    end),
    {Port, Pid}.

stop_server(Pid) ->
    receive
        {cmds, Pid, Cmds} -> Cmds
    after 5000 -> error(server_timeout)
    end.

loop(S, Acc) ->
    case gen_tcp:recv(S, 0, 5000) of
        {ok, Line} ->
            Cmd = chomp(Line),
            handle(S, Cmd, [Cmd | Acc]);
        {error, _} ->
            Acc
    end.

handle(S, "EHLO" ++ _, Acc) ->
    send(S, "250-mock\r\n250-AUTH LOGIN XOAUTH2\r\n250 8BITMIME\r\n"),
    loop(S, Acc);
handle(S, "AUTH LOGIN" ++ _, Acc) ->
    send(S, "535 5.7.3 Authentication unsuccessful\r\n"),
    loop(S, Acc);
handle(S, "AUTH XOAUTH2 " ++ B64, Acc) ->
    Expected = base64:encode(
        list_to_binary(["user=user@example.com", 1, "auth=Bearer ", ?GOOD_TOKEN, 1, 1])
    ),
    case list_to_binary(B64) of
        Expected ->
            send(S, "235 2.7.0 Authentication successful\r\n"),
            loop(S, Acc);
        _ ->
            Err = base64:encode(<<"{\"status\":\"401\",\"schemes\":\"Bearer\"}">>),
            send(S, ["334 ", Err, "\r\n"]),
            {ok, Empty} = gen_tcp:recv(S, 0, 5000),
            send(S, "535 5.7.3 Authentication unsuccessful\r\n"),
            loop(S, [chomp(Empty) | Acc])
    end;
handle(S, "QUIT" ++ _, Acc) ->
    send(S, "221 bye\r\n"),
    Acc;
handle(S, _, Acc) ->
    send(S, "250 ok\r\n"),
    loop(S, Acc).

send(S, Data) -> gen_tcp:send(S, Data).

chomp(Bin) -> string:trim(binary_to_list(Bin), trailing, [[$\r, $\n]]).
