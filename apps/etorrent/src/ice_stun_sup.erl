%% @author Edward Wang <yujiangw@gmail.com>
%% @doc Supervises all processes of ICE/STUN subsystem.
%% @end

-module(ice_stun_sup).
-behaviour(supervisor).

-include("log.hrl").

-ifdef(TEST).
-include_lib("eqc/include/eqc.hrl").
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_link/0,
         add_stun_client/3,
         lookup_stun_client/2
        ]).

-export([init/1]).

-define(SERVER, ?MODULE).


%%===================================================================
%% API
%%===================================================================
start_link() ->
    SupName = {local, ?SERVER},
    supervisor:start_link(SupName, ?MODULE, []).

    
add_stun_client(Host, StunSvr, Sock) ->
    ChildID = stun_client_id(Host, StunSvr),
    ChildSpec = {ChildID,
                 {stun_client, start_link, [Host, StunSvr, Sock]},
                 transient, 2000, worker, dynamic},
    case supervisor:start_child(?SERVER, ChildSpec) of
        {ok, Pid} -> {ok, Pid};
        {error, {already_started, _}} -> ignore
    end.


lookup_stun_client(Host, StunSvr) ->
    ChildID = stun_client_id(Host, StunSvr),
    Children = supervisor:which_children(?SERVER),
    case lists:keyfind(ChildID, 1, Children) of
        false -> {error, not_found};
        {_, Pid, _, _} -> {ok, Pid}
    end.

%%===================================================================
%% supervisor callback
%%===================================================================
init([]) ->
    ICE = {ice, {ice, start_link, []},
                permanent, 2000, worker, [ice]},
    Children = [ICE],
    RestartStrategy = {one_for_one, 1, 60},
    {ok, {RestartStrategy, Children}}.


%%===================================================================
%% private
%%===================================================================
stun_client_id(Host, StunSvr) ->
    {stun_client, Host, StunSvr}.


-ifdef(EUNIT).


-endif.

