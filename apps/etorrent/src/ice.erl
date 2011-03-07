-module(ice).
-behaviour(gen_server).

-include("log.hrl").

-ifdef(TEST).
-include_lib("eqc/include/eqc.hrl").
-include_lib("eunit/include/eunit.hrl").
-endif.


-export([start_link/1,
         start_link/0
         ]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).


-record(state,  {stun_svr   :: {inet:ip_address(), pos_integer()}
                }).


-define(SERVER, ?MODULE).

%% RFC-5389 STUN spec constants.
-define(STUN_PORT, 3478).
-define(STUN_MAGIC_COOKIE, <<16#2112A442:32>>).


start_link() ->
    start_link({{114,243,235,192}, ?STUN_PORT}).


start_link(StunSvr) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [StunSvr], []).


init([StunSvr]) ->
    {ok, #state{stun_svr = StunSvr}, 0}.


handle_call(_Req, _From, State) ->
    {reply, ok, State}.


handle_cast(_Req, State) ->
    {noreply, State}.


handle_info(timeout, State) ->
    #state{stun_svr = StunSvr} = State,
    Addrs = gather_host_candidates(),
    Pairs = pair_with_stun_server(Addrs, StunSvr),
    [begin
        case stun_client:create(Host, StunSvr, Sock) of
            {ok, Pid} ->
                %% gives up ownership of the udp socket, so newly
                %% created stun client will get upcoming udp packets
                gen_udp:controlling_process(Sock, Pid);
            _ -> ignore
        end
    end || {Host, _, Sock} <- Pairs],
    {noreply, State};
handle_info({udp, Socket, IP, Port, Packet}, State) ->
    ?INFO([ice_udp, Socket, IP, Port, Packet]),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.


terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%
%% private
%%
%% return all local addresses in a list
%%
gather_host_candidates() ->
    case erlang:system_info(otp_release) of
    "R14B01" ->
        %% use inet:getifaddrs/0, it returns
        %% {ok, [{"lo0",  [{flags, [...]}, {addr, {...}}]},
        %%       {"eth0", [{flags, [...]}, {addr, {...}}]}]}
        {ok, NICs} = inet:getifaddrs(),
        {_, Attributes} = lists:unzip(NICs),
        AddrTuples = lists:filter(fun(E) ->
                                        {AttrName, _} = E,
                                        AttrName =:= addr
                                    end, lists:append(Attributes)),
        {_, Addrs} = lists:unzip(AddrTuples),
        Addrs;
    _ ->
        %% use undocumented inet:getiflist/0 and inet:ifget/2
        {ok, NICs} = inet:getiflist(),
        %% inet:ifget/2 returns {ok, [{addr, {...}}, {addr, {...}}]}
        AddrTuples = lists:foldl(fun(NIC, Acc) ->
                                    {ok, A} = inet:ifget(NIC, [addr]),
                                    lists:append(A, Acc)
                                end, [], NICs),
        {_, Addrs} = lists:unzip(AddrTuples),
        Addrs
    end.

%%
%% ICE spec only considers usage of a single STUN server.
%% If there are multiple choices, ICE spec indicates
%% an agent SHOULD use a single STUN server for all candidates
%% for a particular session.
%%
pair_with_stun_server(Addrs, StunSvr) ->
    _Pairs = [begin
                case gen_udp:open(0, [binary, {ip, Addr}]) of
                    {ok, Sock} ->
                        {ok, Port} = inet:port(Sock),
                        {{Addr, Port}, StunSvr, Sock};
                    {error, eaddrnotavail} -> ignore
                end
            end || Addr <- Addrs].


%%
%% unit tests
%%
-ifdef(EUNIT).


gather_host_addrs_test() ->
    code:unstick_mod(inet),
    meck:new(inet),
    meck:expect(inet, getifaddrs, fun() -> {ok,[{"lo0",
                                                  [{flags,[up,loopback,running,multicast]},
                                                   {addr,{0,0,0,0,0,0,0,1}},
                                                   {netmask,{65535,65535,65535,65535,65535,65535,65535,65535}},
                                                   {addr,{65152,0,0,0,0,0,0,1}},
                                                   {netmask,{65535,65535,65535,65535,0,0,0,0}},
                                                   {addr,{127,0,0,1}},
                                                   {netmask,{255,0,0,0}}]},
                                                 {"en0",
                                                  [{flags,[up,broadcast,running,multicast]},
                                                   {hwaddr,[0,29,125,213,91,254]},
                                                   {addr,{65152,0,0,0,541,32255,65237,23550}},
                                                   {netmask,{65535,65535,65535,65535,0,0,0,0}},
                                                   {addr,{192,168,1,2}},
                                                   {netmask,{255,255,255,0}},
                                                   {broadaddr,{192,168,1,255}}]},
                                                 {"vboxnet0",
                                                  [{flags,[broadcast,multicast]},{hwaddr,[10,0,39,0,0,0]}]}]}
                                  end),
    Addrs = gather_host_candidates(),
    meck:unload(inet),
    Expected = [{0,0,0,0,0,0,0,1},
                {65152,0,0,0,0,0,0,1},
                {127,0,0,1},
                {65152,0,0,0,541,32255,65237,23550},
                {192,168,1,2}],
    ?assertEqual(Expected, Addrs).


-endif.

