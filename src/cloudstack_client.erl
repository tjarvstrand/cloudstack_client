%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @doc Thin client for the Cloudstack HTTP API
%%% @end
%%% @author Thomas Järvstrand <tjarvstrand@gmail.com>
%%% @copyright
%%% Copyright 2014 Thomas Järvstrand <tjarvstrand@gmail.com>
%%%
%%% This file is part of cloudstack_client
%%%
%%% cloudstack_client is free software: you can redistribute it and/or modify
%%% it under the terms of the GNU Lesser General Public License as published by
%%% the Free Software Foundation, either version 3 of the License, or
%%% (at your option) any later version.
%%%
%%% cloudstack_client is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%%% GNU Lesser General Public License for more details.
%%%
%%% You should have received a copy of the GNU Lesser General Public License
%%% along with cloudstack_client. If not, see <http://www.gnu.org/licenses/>.
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration =======================================================
-module(cloudstack_client).

%%%_* Exports ==================================================================

%% APIr
-export([request/2,
         request/3]).

%%%_* Includes =================================================================

-include_lib("eunit/include/eunit.hrl").

%%%_* Defines ==================================================================

%%%_* Types ====================================================================

-type config() :: #{config_key() => config_param()}.
-type config_key() :: apikey |
                      expires |
                      log_fun |
                      metric_fun |
                      request_fun |
                      secretkey |
                      timeout |
                      url.

-type config_param() :: apikey() |
                        expires() |
                        log_fun() |
                        metric_fun() |
                        request_fun() |
                        secretkey() |
                        timeout() |
                        http_uri:uri().

-type parameters() :: #{atom() => parameter()}.
-type parameter() :: string() |
                     number() |
                     boolean() |
                     [parameter()] |
                     #{atom() => parameter()}.

-type apikey() :: string().

-type expires() :: erlang:timestamp().

-type log_fun() :: fun((Lvl :: debug | info | error,
                        Fmt :: string(),
                        Args :: [term()]) -> any()) |
                   {module(), atom()} |
                   {module(), atom(), [term()]}.
-type metric_fun() :: fun((Type :: counter | timer,
                           Key  :: [atom()]) -> any()) |
                      {module(), atom()} |
                      {module(), atom(), [term()]}.

-type request_fun() :: fun((http_uri:uri(), timeout()) ->
                              {ok, {http_uri:status_code(), json()}}) |
                       {module(), atom()} |
                       {module(), atom(), [term()]}.

-type secretkey() :: string().

-type json() :: string().

%%%_* API ======================================================================

%%------------------------------------------------------------------------------
%% @equiv request(Config, Call, Params, fun(_) -> ok end).
%% @end
-spec request(Config :: config(),
              Call   :: atom()) -> {ok, Body :: string()} |
                                   {error, Rsn :: term()}.
%%------------------------------------------------------------------------------
request(Config, Call) ->
  request(Config, Call, #{}).

%%------------------------------------------------------------------------------
%% @doc Issue a request
%% @end
-spec request(Config :: config(),
              Call   :: atom(),
              Params :: parameters()) -> {ok, Body :: json()} |
                                         {error, Rsn :: term()}.
%%------------------------------------------------------------------------------
request(Config0, Call, Params) ->
  do_request(maps:merge(default_config(), Config0), Call, Params).

%%%_* Internal functions =======================================================

do_request(Config, Call, Params) ->
  Url = url(Config, Call, Params),
  {ok, {_, _, Host, _, _, _}} = http_uri:parse(Url),
  log(Config, info, "Issuing ~p to ~s", [Call, Host]),
  log(Config, debug, "Issuing request to ~p", [Url]),
  metric(Config, counter, [cloudstack_client, request, issue], 1),
  Start = ms_timestamp(os:timestamp()),
  case call(request_fun, Config, [Url, maps:get(timeout, Config)]) of
    {error, Rsn} = Err            ->
      log(Config, error, "Request Failed: ~p", [Rsn]),
      metric(Config, counter, [cloudstack_client, request, failure], 1),
      Err;
    {ok,   {Resp, Body}} ->
      metric(Config, counter, [cloudstack_client, request, success], 1),
      Duration = ms_timestamp(os:timestamp()) - Start,
      metric(Config, timer, [cloudstack_client, request, duration], Duration),
      log(Config, info, "Request ~p to ~s done with result ~p in ~.2fs",
          [Call, Host, Resp, Duration/1000000]),
      log(Config, debug, "Response Body: ~p", [Body]),
      {ok, Body}
  end.

ms_timestamp({Mega,Sec,Micro}) -> (Mega*1000000+Sec)*1000000+Micro.

log(Config, Lvl, Fmt, Args) ->
  call(log_fun, Config, [Lvl, Fmt, Args]).

metric(Config, Type, Key, Value) ->
  call(metric_fun, Config, [Type, Key, Value]).

call(Key, Config, Args) ->
  do_call(maps:get(Key, Config), Args).

do_call(Fun, Args) when is_function(Fun) ->
  erlang:apply(Fun, Args);
do_call({Mod, Fun}, Args) ->
  erlang:apply(Mod, Fun, Args);
do_call({Mod, Fun, BaseArgs}, Args) ->
  erlang:apply(Mod, Fun, BaseArgs ++ Args).

default_config() ->
  GNow = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
  #{apikey              => "",
    expires             => calendar:gregorian_seconds_to_datetime(GNow + 60),
    log_fun             => fun(debug, _,   _)    -> ok;
                              (Lvl,   Fmt, Args) ->
                               io:format("~p: " ++ Fmt ++ "\n", [Lvl|Args])
                           end,
    metric_fun          => fun(_, _, _) -> ok end,
    request_fun         => fun(Url, Timeout) ->
                               httpc:request(get,
                                             {Url, []},
                                             [{timeout, Timeout}],
                                             [{full_result, false}])
                           end,
    secretkey           => "",
    timeout             => 6000, % 1 min
    url                 => ""
   }.

url(Config, Call, Params0) ->
  Url = maps:get(url, Config),
  Params = Params0#{apikey => maps:get(apikey, Config),
                    command => atom_to_list(Call),
                    response => "json",
                    signatureversion => "3",
                    expires => fmt_expires(maps:get(expires, Config))
                   },
  EncodedParams = params_str(Params),
  Sig = sig_str(maps:get(secretkey, Config), EncodedParams),
  lists:flatten(io_lib:format("~s?~s&signature=~s", [Url, EncodedParams, Sig])).

sig_str(Key, ParamsStr0) ->
  ParamsStr = string:to_lower(ParamsStr0),
  Base64 = binary_to_list(base64:encode(crypto:hmac(sha, Key, ParamsStr))),
  space_to_plus(string:strip(http_uri:encode(Base64))).

params_str(Params) ->
  ParamStrs = maps:fold(fun(K, V, A) ->  [param_str(K, V)| A] end, [], Params),
  space_to_plus(string:join(lists:sort(ParamStrs), "&")).

param_str(ParentK, ParentV) when is_map(ParentV)     ->
  {_, Res} =
    maps:fold(fun(K, V0, {I, Strs}) ->
                  V = http_uri:encode(param_val_string(V0)),
                  Str = lists:flatten(
                          io_lib:format("~p[~p].key=~p&~p[~p].value=~s",
                                        [ParentK, I, K, ParentK, I, V])),
                  {I + 1, [Str|Strs]}
              end,
              {0, ""},
              ParentV),
  string:join(lists:reverse(Res), "&");
param_str(K, V) ->
  param_key_string(K) ++ "=" ++ http_uri:encode(param_val_string(V)).

param_key_string(K) ->
  string:to_lower(atom_to_list(K)).

param_val_string(V) when is_boolean(V)              ->
  atom_to_list(V);
param_val_string(V) when is_integer(V)              ->
  integer_to_list(V);
param_val_string(V) when is_float(V)                ->
  float_to_list(V, [{decimals, 2}]);
param_val_string([E|_] = Vs) when not is_integer(E)  ->
  string:join([param_val_string(V) || V <- Vs], ",");
param_val_string(V)                                 ->
  V.

space_to_plus(Str) ->
  re:replace(Str, "%20", "+", [global, {return, list}]).

fmt_expires({{Y, M, D}, {H, Min, S}}) ->
  lists:flatten(io_lib:format("~4..0b-~2..0b-~2..0bT~2..0b:~2..0b:~2..0b+0000",
                              [Y, M, D, H, Min, S])).

%%%_* Tests ====================================================================


request_test() ->
  Config = #{url       => "http://foo",
             apikey    => "7QkpR9cRliHdIfOtBwfo92CglaXgw4Sve2ZQksocolW-eWFbcApo"
                          "RmpuMXrXBsn5rXSByW217uiJB9F2wfbNnQ",
             secretkey => "1W60cZH-4tKm9Lb_8GaAbDrO7eP4_ZCKuOGpK0wzpPucqM8X5ylw"
                          "iCv3pkfhV8bVwsya149TtDsmn0tpyUWpRw"},
  ReqFunA = fun(_, _) -> {ok, {"Response", "foo"}} end,
  ?assertEqual({ok, "foo"},
               request(Config#{request_fun => ReqFunA}, a_request)),
  ReqFunB = fun(_, _) -> {error, terrible_mistake} end,
  ?assertEqual({error, terrible_mistake},
               request(Config#{request_fun => ReqFunB}, a_request)).

call_test_() ->
  [?_assertEqual(1, call(my_fun, #{my_fun => fun() -> 1 end}, [])),
   ?_assertEqual(2, call(my_fun, #{my_fun => fun(A) -> A end}, [2])),
   ?_assertEqual(atom, call(my_fun, #{my_fun => {erlang, list_to_atom}}, ["atom"])),
   ?_assertEqual(atom, call(my_fun, #{my_fun => {erlang, list_to_atom, ["atom"]}}, []))
  ].

default_config_test() ->
  ?assert(is_map(default_config())).

expires_test_() ->
  [?_assertEqual("2014-07-02T16:17:24+0000",
                  fmt_expires({{2014,7,2}, {16,17, 24}}))
  ].

space_to_plus_test_() ->
  [?_assertEqual("+",   http_uri:decode(space_to_plus(http_uri:encode(" ")))),
   ?_assertEqual("+",   http_uri:decode(space_to_plus(http_uri:encode("+")))),
   ?_assertEqual("%20", http_uri:decode(space_to_plus(http_uri:encode("%20"))))
  ].

param_key_string_test_() ->
  [?_assertEqual("foo", param_key_string(foo)),
   ?_assertError(badarg, param_key_string(1))
  ].

param_val_string_test_() ->
  [?_assertEqual("foo=bar",  param_str(foo, "bar")),
   ?_assertEqual("foo=true", param_str(foo, true)),
   ?_assertEqual("foo=1",    param_str(foo, 1)),
   ?_assertEqual("foo=1.00", param_str(foo, 1.0)),
   ?_assertEqual("foo[0].key=bar&foo[0].value=ba%26z&"
                 "foo[1].key=baz&foo[1].value=bam",
                 param_str(foo, #{bar => "ba&z", baz => "bam"})),
   ?_assertEqual("foo=a%2Cb", param_str(foo, ["a","b"]))
  ].

params_str_test_() ->
  [?_assertEqual("baz=b+am&foo=bar",
                 params_str(#{foo => "bar", baz => "b am"}))
  ].

sig_str_test_() ->
  Key = "1W60cZH-4tKm9Lb_8GaAbDrO7eP4_ZCKuOGpK0wzpPucqM8X5ylwiCv3pkfhV8bVwsyO149TtDsmn0tpyUWpRw",
  [?_assertEqual("nuPDsItzZE2so%2BQ2clT2VGneHTM%3D", sig_str(Key, "baz=b+am&foo=bar"))
  ].

url_test_() ->
  Now = {{2014,7,3},{14,46,38}},
  Config = #{apikey    => "7QkpR9cRliHdIfOtBwfo92CglaXgw4Sve2ZQksocolW-eWFbcApo"
                          "RmpuMXrXBsn5rXSByW217uiJB9F2wfbNnQ",
             secretkey => "1W60cZH-4tKm9Lb_8GaAbDrO7eP4_ZCKuOGpK0wzpPucqM8X5ylw"
                          "iCv3pkfhV8bVwsya149TtDsmn0tpyUWpRw",
             url       => "https://my-cloud/portal/client/apis/"
                          "ccpapi01",
            expires    => Now},
  [?_assertEqual("https://my-cloud/portal/client/apis/ccpapi01?apikey=7QkpR9cRl"
                 "iHdIfOtBwfo92CglaXgw4Sve2ZQksocolW-eWFbcApoRmpuMXrXBsn5rXSByW"
                 "217uiJB9F2wfbNnQ&command=listNetworks&expires=2014-07-03T14%3"
                 "A46%3A38%2B0000&response=json&signatureversion=3&signature=h5"
                 "JhZQDFRY%2FGhcsGTM0yovekUVE%3D",
                 url(Config, 'listNetworks', #{}))
  ].

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
