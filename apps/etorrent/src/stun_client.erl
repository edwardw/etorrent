-module(stun_client).
-behaviour(gen_server).

-include("log.hrl").

-export([start_link/3,
         create/3,
         send_stun_binding/2
         ]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-type socket()::_.
-record(state,  {sock       :: socket(),
                 host       :: {inet:ip_address(), 1..65535},   %% host addr
                 stun_svr   :: {inet:ip_address(), 1..65535},   %% stun server addr
                 tid        :: binary()
                }).


-define(SERVER, ?MODULE).

%% RFC-5389 STUN spec constants.
-define(STUN_PORT, 3478).
-define(STUN_MAGIC_COOKIE, <<16#2112A442:32>>).


%%===================================================================
%% API
%%===================================================================
start_link(Host, StunSvr, Sock) ->
    ?INFO([Host, StunSvr, Sock]),
    gen_server:start_link(?MODULE, [Host, StunSvr, Sock], []).


create(Host, StunSvr, Sock) ->
    ice_stun_sup:add_stun_client(Host, StunSvr, Sock).


send_stun_binding(Host, StunSvr) ->
    case lookup_pid(Host, StunSvr) of
        {ok, Pid} ->
            gen_server:cast(Pid, {send_stun_binding});
        {error, not_found} ->
            ignore
    end.


%%===================================================================
%% gen_server callbacks
%%===================================================================
init([Host, StunSvr, Sock]) ->
    {ok, #state{host = Host, stun_svr = StunSvr, sock = Sock}}.


handle_call(_Req, _From, State) ->
    {reply, ok, State}.


handle_cast({send_stun_binding}, State) ->
    #state{stun_svr = StunSvr, sock = Sock} = State,
    case do_send_stun_binding(StunSvr, Sock) of
        {ok, Tid} ->
            {noreply, State#state{tid = Tid}};
        {error, stop} ->
            {stop, error_send_stun_binding, State}
    end;
handle_cast(_Req, State) ->
    {noreply, State}.


handle_info({udp, Socket, IP, Port, Packet}, State) ->
    #state{tid = Tid} = State,
    case verify_stun_resp(Tid, Packet) of
        valid ->
            Attrs = parse_stun_resp(Packet),
            ?INFO({stun_resp, Attrs});
        {tid_not_exist, Tid} ->
            ?INFO({tid_not_exist, Tid});
        invalid ->
            ?INFO({malformed_stun_response, IP, Port, Packet})
    end,
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.


terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%===================================================================
%% private
%%===================================================================
lookup_pid(Host, StunSvr) ->
    ice_stun_sup:lookup_stun_client(Host, StunSvr).


do_send_stun_binding(StunSvr, Sock) ->
    %% transaction id. is cryptographic random necessary? or a radom:uniform/1 sufficient?
    Tid = crypto:rand_bytes(12),
    {StunSvrAddr, StunSvrPort} = StunSvr,
    BindingReq = <<0:2, 16#1:14, 0:16, ?STUN_MAGIC_COOKIE/binary, Tid/binary>>,
    case gen_udp:send(Sock, StunSvrAddr, StunSvrPort, BindingReq) of
        ok ->
            ?INFO({sent, BindingReq}),
            {ok, Tid};
        {error, eafnosupport} ->
            {error, stop};
        {error, enetunreach} ->
            {error, stop}
    end.


verify_stun_resp(MyTid, Resp) ->
    <<MultiplexBits:2, MsgType:14, MsgLen:16, MagicCookie:32, Tid:96, Payload/binary>> = Resp,
    case MultiplexBits =:= 0 andalso
         is_stun_resp(MsgType) andalso
         size(Payload) =:= MsgLen andalso
         <<MagicCookie:32>> =:= ?STUN_MAGIC_COOKIE of
        true ->
            case MyTid =:= <<Tid:96>> of
                true -> valid;
                false -> {tid_not_exist, Tid}
            end;
        false -> invalid
    end.

is_stun_resp(MsgType) ->
    %% either success response or error response for binding request
    MsgType =:= 2#00000100000001 orelse MsgType =:= 2#00000100010001.


parse_stun_resp(Resp) ->
    %% RFC-5389 section 6: stun message structure
    <<_:2, _:14, _MsgLen:16, _:32, Tid:96, Payload/binary>> = Resp,
    parse_stun_resp_payload(Tid, Payload).

parse_stun_resp_payload(Tid, Payload) ->
    parse_stun_resp_payload(Tid, Payload, []).
parse_stun_resp_payload(_Tid, <<>>, Acc) ->
    Acc;
parse_stun_resp_payload(Tid, Payload, Acc) ->
    <<AttrType:16, AttrLen:16, R/binary>> = Payload,
    <<Value:AttrLen/binary, Rest/binary>> = R,
    case AttrType of
        16#0001 ->
            %% MAPPED-ADDRESS
            %% @todo: should be easy to make this work for ipv6, too.
            <<0:8, _Family:8, Port:16, Addr/binary>> = Value,
            <<A, B, C, D>> = Addr,
            parse_stun_resp_payload(Tid, Rest, [{mapped_address, Tid, {A, B, C, D}, Port}|Acc]);
        _ ->
            parse_stun_resp_payload(Tid, Rest, Acc)
    end.

