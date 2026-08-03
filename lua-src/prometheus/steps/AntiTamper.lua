local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local Parser = require("prometheus.parser");
local Enums = require("prometheus.enums");
local logger = require("logger");
local AntiTamper = Step:extend();
AntiTamper.Description = "Injects a multi-layer, Roblox-specific anti-tamper system. Requires a Roblox (Luau) environment - the generated code hard-fails if the 'game' global is unavailable, so this step is not suitable for non-Roblox Lua targets.";
AntiTamper.Name = "Anti Tamper";
AntiTamper.SettingsDescriptor = {
    UseDebug = {
        type = "boolean",
        default = true,
        description = "Include debug‑library checks (gethook, etc.). Recommended."
    },
    DiagnosticMode = {
        type = "boolean",
        default = false,
        description = "If true, returns a report table instead of erroring."
    }
}
function AntiTamper:init(settings)
    self.UseDebug = settings and settings.UseDebug ~= false
    self.DiagnosticMode = settings and settings.DiagnosticMode or false
end
function AntiTamper:apply(ast, pipeline)
    if pipeline.PrettyPrint then
        logger:warn(string.format("\"%s\" cannot be used with PrettyPrint, ignoring \"%s\"", self.Name, self.Name));
        return ast;
    end
    local antiTamperFunc = [=[
        local function anti_tamper(diagnostic_mode, use_debug)
            local __line_ref = nil
            local is_loadstring = false
            if use_debug and type(debug) == "table" and type(debug.getinfo) == "function" then
                local ok_ls, info_ls = pcall(debug.getinfo, 1, "S")
                if ok_ls and info_ls and info_ls.source then
                    is_loadstring = (info_ls.source:sub(1,1) == "=")
                end
            end
            if use_debug and type(debug) == "table" and type(debug.getinfo) == "function" then
                local ok_line, info_line = pcall(debug.getinfo, 1, "l")
                if ok_line and type(info_line) == "table" then
                    __line_ref = info_line.currentline
                end
            end
            if not game or not game.GetService then
                return error("Tamper: Invalid environment", 0)
            end
            local _pcall = pcall
            local _error = error
            local _getfenv = getfenv
            local _setfenv = setfenv
            local _debug = debug
            local _string_dump = string.dump
            if rawget(_G, "hookfunction") ~= nil or rawget(_G, "replaceclosure") ~= nil then
                return _error("Tamper: hookfunction/replaceclosure present", 0)
            end
            local function integrity_check(fn)
                if type(_string_dump) ~= "function" then
                    return true
                end
                local ok, dumped = _pcall(_string_dump, fn)
                if not ok then
                    return true
                end
                return type(dumped) == "string" and #dumped > 10
            end
            local ic_result = integrity_check(anti_tamper)
            if not ic_result then
                return _error("Tamper: function modified", 0)
            end
            if use_debug and _debug then
                if type(_debug.gethook) == "function" then
                    local ok_hook, hook = _pcall(_debug.gethook)
                    if ok_hook and hook ~= nil then
                        return _error("Tamper: debug hook detected", 0)
                    end
                end
            end
            do
                local ok_clock, t1 = pcall(os.clock)
                if ok_clock then
                    for i = 1, 1e4 do end
                    local _, t2 = pcall(os.clock)
                    local elapsed = t2 and (t2 - t1) or 0
                    if t2 and elapsed > 2 then
                        return _error("Tamper: execution slowed", 0)
                    end
                end
            end
            if _VERSION ~= "Luau" then
                local mt = getmetatable(_G)
                if mt and (mt.__index or mt.__newindex) then
                    return _error("Tamper: global metatable hooked", 0)
                end
            end
            if _string_dump and _VERSION ~= "Luau" then
                local ok = _pcall(_string_dump, function() end)
                if not ok then
                    return _error("Tamper: dump blocked (hooked)", 0)
                end
            end
            local report = {
                hard_failures = {},
                soft_signals = {},
                passed = {},
            }
            local function hard(name, value)
                report.hard_failures[#report.hard_failures + 1] = {
                    check = name,
                    value = value,
                }
            end
            local function soft(name, value)
                report.soft_signals[#report.soft_signals + 1] = {
                    check = name,
                    value = value,
                }
            end
            local function pass(name, value)
                report.passed[#report.passed + 1] = {
                    check = name,
                    value = value,
                }
            end
            local function safe_call(fn, ...)
                if type(fn) ~= "function" then
                    return false, "not a function"
                end
                return pcall(fn, ...)
            end
            local function value_type(value)
                if type(typeof) == "function" then
                    local ok, result = pcall(typeof, value)
                    if ok then return result end
                end
                return type(value)
            end
            local function read_member(object, member)
                return object[member]
            end
            local function write_member(object, member, value)
                object[member] = value
            end
            local _bit = bit32 or (type(bit) == "table" and bit) or nil
            local _bxor = _bit and _bit.bxor or function(a, b)
                local result, bit_val = 0, 1
                while a > 0 or b > 0 do
                    local ab, bb = a % 2, b % 2
                    if ab ~= bb then result = result + bit_val end
                    a, b, bit_val = math.floor(a / 2), math.floor(b / 2), bit_val * 2
                end
                return result
            end
            local _band = _bit and _bit.band or function(a, b)
                local result, bit_val = 0, 1
                while a > 0 and b > 0 do
                    if a % 2 == 1 and b % 2 == 1 then result = result + bit_val end
                    a, b, bit_val = math.floor(a / 2), math.floor(b / 2), bit_val * 2
                end
                return result
            end
            local function xor_decode(key, ...)
                local out = {}
                for i = 1, select("#", ...) do
                    out[i] = string.char(_band(_bxor(select(i, ...), key), 255))
                end
                return table.concat(out)
            end
            local function encode_probe_string(input)
                local encoded = {}
                local state = (#input * 257) % 65536
                for i = 1, #input do
                    local b = string.byte(input, i)
                    encoded[i] = string.format("%02x", _bxor(b, _band(state, 255)))
                    state = _band(state * 31 + i, 65535)
                end
                return table.concat(encoded)
            end
            local function identity_self_test()
                local nan = 0/0
                if nan ~= nan then return true end
                return false
            end
            local function at_closure_a() return 57005 end
            local function at_closure_b() return 123 end
            local function at_closure_c() return 1 end
            local function at_closure_d() return 2 end
            local function raise_named_probe_error() error("__ntt_probe__", 0) end
            local function build_runtime_fingerprint(value)
                local str_val = "??"
                local ok, cv = pcall(tostring, value)
                if ok then str_val = cv end
                local time_byte = _band(math.floor(((tick and tick()) or 0) * 997), 255)
                local fp = string.format("%x:%s:%x", tonumber(value) or 0, str_val, time_byte)
                pcall(function() error("", 0) end)
                pcall(function()
                    local t = coroutine.running()
                    if t then coroutine.status(t) end
                end)
                pcall(function()
                    if task and coroutine then
                        local t = coroutine.running()
                        if t then task.spawn(function() coroutine.status(t) end) end
                    end
                end)
                return fp
            end
            local function check_forbidden_globals()
                local env = _G
                if type(getgenv) == "function" then
                    local ok, result = pcall(getgenv)
                    if ok and type(result) == "table" then env = result end
                end
                if type(env) ~= "table" then
                    hard("global_environment_is_not_table", type(env))
                    return
                end
                local forbidden = {
                    "__LARRY_FAILOPEN_CHILD_LOOKUPS",
                    "__LARRY_FAILOPEN_MEMBER_INDEX",
                    "__LARRY_FAILOPEN_ENUM_MEMBERS",
                    "__LARRY_FAILOPEN_PROPERTY_TYPES",
                    "__LARRY_FAILOPEN_MEMBER_NEWINDEX",
                    "__LARRY_SKIP_ASYNC_EXECUTION",
                    "__LARRY_ARGV_DEBUG",
                    "__LARRY_CLI_CONFIG_ARG",
                    "__LARRY_TIMEOUT_SECONDS",
                    "__LARRY_MAX_SIMULATED_SECONDS",
                    "__LARRY_CALL_LOG_ENABLED",
                    "__LARRY_FUNCTION_LOG_ENABLED",
                    "__LARRY_PREMIUM",
                    "__LARRY_PREMIUM_USER",
                    "__LARRY_IS_PREMIUM",
                    "__larry_internal",
                    "__larry_native_string_pack_raw",
                    "__larry_native_string_unpack_raw",
                    "LARRY_CLI_CONFIG_PERSIST",
                    "LARRY_CALL_LOG_ENABLED_PERSIST",
                    "LARRY_FUNCTION_LOG_ENABLED_PERSIST",
                }
                for _, name in ipairs(forbidden) do
                    local value = rawget(env, name)
                    if value ~= nil then
                        if is_loadstring then
                            soft("loadstring_forbidden:" .. name, value_type(value))
                        else
                            hard("forbidden_global_present:" .. name, value_type(value))
                        end
                    else
                        pass("forbidden_global_absent:" .. name, true)
                    end
                end
                for key in pairs(env) do
                    if type(key) == "string" then
                        local lower_key = string.lower(key)
                        if string.sub(lower_key, 1, 10) == "__larry__"
                            or string.sub(lower_key, 1, 8) == "b_larry_"
                            or string.find(lower_key, "larry", 1, true) == 1 then
                            hard("forbidden_global_pattern:" .. key, true)
                        end
                    end
                end
            end
            local function check_known_executor_globals()
                -- Curated list of globals that only exist inside Roblox script
                -- executors (Synapse, Script-Ware, KRNL, and similar), never in a
                -- stock Roblox client. Legitimate scripts have no reason to define
                -- any of these names, so their presence is a strong tamper signal.
                -- A handful of individually-notable ones (getgenv, hookfunction,
                -- clonefunction, getcallingscript, getrawmetatable) are already
                -- checked elsewhere in this file and are intentionally left out
                -- here to avoid duplicate reports.
                local KNOWN_EXECUTOR_GLOBALS = {
                    "getrenv", "getsenv", "setrawmetatable",
                    "hookfunc", "hookmetamethod", "newcclosure",
                    "cloneref", "compareinstances",
                    "iscclosure", "islclosure", "isexecutorclosure", "checkclosure", "isourclosure",
                    "checkcaller",
                    "getconnections", "firesignal", "fireclickdetector", "fireproximityprompt", "firetouchinterest",
                    "getgc", "getinstances", "getnilinstances", "getscripts", "getrunningscripts",
                    "getloadedmodules", "getactors",
                    "getscriptbytecode", "dumpstring", "getscripthash", "getscriptclosure", "decompile",
                    "readfile", "writefile", "appendfile", "loadfile", "listfiles",
                    "isfile", "isfolder", "makefolder", "delfolder", "delfile",
                    "setclipboard", "toclipboard", "getclipboard", "setrbxclipboard",
                    "queue_on_teleport", "queueonteleport",
                    "setthreadidentity", "getthreadidentity",
                    "setidentity", "getidentity", "setthreadcontext", "getthreadcontext",
                    "getnamecallmethod", "setnamecallmethod",
                    "isreadonly", "setreadonly",
                    "gethiddenproperty", "sethiddenproperty", "isscriptable", "setscriptable",
                    "identifyexecutor", "getexecutorname",
                    "http_request", "syn",
                    "cleardrawcache", "isrenderobj",
                    "crypt",
                    "lz4compress", "lz4decompress",
                    "mouse1click", "mouse1press", "mouse1release",
                    "mouse2click", "mouse2press", "mouse2release",
                    "mousemoveabs", "mousemoverel", "mousescroll",
                    "gethui", "getcustomasset", "getcallbackvalue", "messagebox",
                    "isrbxactive", "isgameactive", "setfpscap",
                    "getregistry", "getreg", "getstack",
                    "rconsoleclear", "rconsolecreate", "rconsoledestroy",
                    "rconsoleinput", "rconsoleprint", "rconsolesettitle", "rconsolename",
                    "run_on_actor", "runonactor",
                }
                local env = _G
                if type(getgenv) == "function" then
                    local ok, result = pcall(getgenv)
                    if ok and type(result) == "table" then env = result end
                end
                if type(env) ~= "table" then
                    pass("executor_globals_environment_unavailable", true)
                    return
                end
                local found_any = false
                for _, name in ipairs(KNOWN_EXECUTOR_GLOBALS) do
                    local value = rawget(env, name)
                    if value ~= nil then
                        found_any = true
                        if is_loadstring then
                            soft("known_executor_global_present:" .. name, value_type(value))
                        else
                            hard("known_executor_global_present:" .. name, value_type(value))
                        end
                    end
                end
                if not found_any then
                    pass("known_executor_globals_absent", true)
                end
            end
            local function check_debug_hook()
                if not use_debug then return end
                if type(debug) ~= "table" then
                    pass("debug_table_unavailable", true)
                    return
                end
                if type(debug.gethook) ~= "function" then
                    pass("debug_gethook_unavailable", true)
                    return
                end
                local thread = nil
                if type(coroutine) == "table" and type(coroutine.running) == "function" then
                    local ok, current = pcall(coroutine.running)
                    if ok then thread = current end
                end
                local ok, hook, mask, count
                if thread ~= nil then
                    ok, hook, mask, count = pcall(debug.gethook, thread)
                else
                    ok, hook, mask, count = pcall(debug.gethook)
                end
                if not ok then
                    soft("debug_gethook_failed", hook)
                    return
                end
                if hook ~= nil then
                    soft("debug_hook_installed", {
                        hook_type = type(hook),
                        mask = mask,
                        count = count,
                    })
                else
                    pass("debug_hook_absent", true)
                end
            end
            local function check_line_consistency()
                if not use_debug then return end
                if is_loadstring then
                    return
                end
                if type(__line_ref) ~= "number" or __line_ref <= 0 then
                    pass("line_consistency_unavailable", true)
                    return
                end
                if type(debug) ~= "table" or type(debug.getinfo) ~= "function" then
                    pass("line_consistency_debug_unavailable", true)
                    return
                end
                local ok, info = pcall(debug.getinfo, 1, "l")
                if not ok or type(info) ~= "table" then
                    soft("line_consistency_probe_failed", info)
                    return
                end
                if info.currentline ~= __line_ref then
                    hard("line_consistency_mismatch", {
                        expected = __line_ref,
                        actual = info.currentline,
                    })
                else
                    pass("line_consistency_valid", true)
                end
            end
            local function check_coroutine_state()
                if type(coroutine) ~= "table" then
                    hard("coroutine_table_missing", type(coroutine))
                    return
                end
                if type(coroutine.running) ~= "function" then
                    hard("coroutine_running_missing", type(coroutine.running))
                    return
                end
                if type(coroutine.status) ~= "function" then
                    hard("coroutine_status_missing", type(coroutine.status))
                    return
                end
                local ok_running, thread = pcall(coroutine.running)
                if not ok_running then
                    soft("coroutine_running_failed", thread)
                    return
                end
                if thread == nil then
                    pass("coroutine_has_no_thread", true)
                    return
                end
                local ok_status, status = pcall(coroutine.status, thread)
                if not ok_status then
                    soft("coroutine_status_failed", status)
                    return
                end
                if status ~= "running" then
                    soft("current_coroutine_not_running", status)
                else
                    pass("current_coroutine_running", true)
                end
            end
            local function get_service(game_object, name)
                local ok, service = safe_call(game_object.GetService, game_object, name)
                if not ok then
                    hard("get_service_failed:" .. name, service)
                    return nil
                end
                return service
            end
            local function expect_instance(name, object, class_name)
                local actual_type = value_type(object)
                if actual_type ~= "Instance" then
                    hard("service_not_instance:" .. name, actual_type)
                    return false
                end
                local actual_class = nil
                local ok_class, class_value = pcall(read_member, object, "ClassName")
                if ok_class then actual_class = class_value end
                if actual_class ~= class_name then
                    hard("wrong_class_name:" .. name, actual_class)
                    return false
                end
                if type(object.IsA) == "function" then
                    local ok_is_a, is_a = pcall(object.IsA, object, class_name)
                    if not ok_is_a or is_a ~= true then
                        hard("isa_failed:" .. name, is_a)
                        return false
                    end
                end
                pass("valid_instance:" .. name, class_name)
                return true
            end
            local function check_roblox_services()
                local game_object = game
                if game_object == nil then
                    hard("game_missing", nil)
                    return nil
                end
                if type(game_object.GetService) ~= "function" then
                    hard("game_getservice_missing", type(game_object.GetService))
                    return nil
                end
                if value_type(game_object) ~= "Instance" then
                    hard("game_not_instance", value_type(game_object))
                end
                local game_class = nil
                local ok_game_class, game_class_value = pcall(read_member, game_object, "ClassName")
                if ok_game_class then game_class = game_class_value end
                if game_class ~= "DataModel" then
                    hard("game_wrong_class", game_class)
                else
                    pass("game_is_datamodel", true)
                end
                local run_service_a = get_service(game_object, "RunService")
                local run_service_b = get_service(game_object, "RunService")
                local players = get_service(game_object, "Players")
                local workspace_service = get_service(game_object, "Workspace")
                if run_service_a ~= nil and run_service_b ~= nil then
                    if run_service_a ~= run_service_b then
                        soft("getservice_identity_changed:RunService", true)
                    else
                        pass("getservice_identity_stable:RunService", true)
                    end
                end
                if run_service_a ~= nil then
                    expect_instance("RunService", run_service_a, "RunService")
                    if type(run_service_a.IsClient) ~= "function" then
                        hard("runservice_isclient_missing", type(run_service_a.IsClient))
                    else
                        local ok_client, is_client = pcall(run_service_a.IsClient, run_service_a)
                        if not ok_client or is_client ~= true then
                            soft("not_running_on_client", is_client)
                        else
                            pass("running_on_client", true)
                        end
                    end
                    local ok_heartbeat, heartbeat = pcall(read_member, run_service_a, "Heartbeat")
                    if not ok_heartbeat or value_type(heartbeat) ~= "RBXScriptSignal" then
                        hard("heartbeat_invalid", value_type(heartbeat))
                    else
                        pass("heartbeat_valid", true)
                    end
                    local ok_render, render_stepped = pcall(read_member, run_service_a, "RenderStepped")
                    if ok_render and render_stepped ~= nil then
                        if value_type(render_stepped) ~= "RBXScriptSignal" then
                            hard("renderstepped_invalid", value_type(render_stepped))
                        else
                            pass("renderstepped_valid", true)
                        end
                    end
                end
                if players ~= nil then
                    expect_instance("Players", players, "Players")
                    local ok_local_player, local_player = pcall(read_member, players, "LocalPlayer")
                    if not ok_local_player or value_type(local_player) ~= "Instance" then
                        hard("localplayer_invalid", value_type(local_player))
                    else
                        local ok_is_player, is_player = safe_call(local_player.IsA, local_player, "Player")
                        if not ok_is_player or is_player ~= true then
                            hard("localplayer_not_player", is_player)
                        elseif local_player.Parent ~= players then
                            hard("localplayer_wrong_parent", value_type(local_player.Parent))
                        else
                            pass("localplayer_valid", true)
                        end
                    end
                end
                if workspace_service ~= nil then
                    expect_instance("Workspace", workspace_service, "Workspace")
                end
                return {
                    game = game_object,
                    run_service = run_service_a,
                    players = players,
                    workspace = workspace_service,
                }
            end
            local function destroy_instance(object)
                if object ~= nil and type(object.Destroy) == "function" then
                    pcall(object.Destroy, object)
                end
            end
            local function check_instance_properties()
                if type(Instance) ~= "table" or type(Instance.new) ~= "function" then
                    hard("instance_constructor_missing", type(Instance))
                    return
                end
                local checks = {
                    { class = "Part", property = "CFrame", expected = "CFrame" },
                    { class = "Part", property = "Position", expected = "Vector3" },
                    { class = "Part", property = "Material", expected = "EnumItem" },
                    { class = "Model", property = "WorldPivot", expected = "CFrame" },
                    { class = "Model", property = "PrimaryPart", expected = "nil" },
                    { class = "BoolValue", property = "Value", expected = "boolean" },
                    { class = "StringValue", property = "Value", expected = "string" },
                    { class = "ObjectValue", property = "Value", expected = "nil" },
                    { class = "Vector3Value", property = "Value", expected = "Vector3" },
                    { class = "CFrameValue", property = "Value", expected = "CFrame" },
                    { class = "Color3Value", property = "Value", expected = "Color3" },
                    { class = "BrickColorValue", property = "Value", expected = "BrickColor" },
                    { class = "RayValue", property = "Value", expected = "Ray" },
                    { class = "ScreenGui", property = "DisplayOrder", expected = "number" },
                    { class = "ScreenGui", property = "IgnoreGuiInset", expected = "boolean" },
                    { class = "UICorner", property = "CornerRadius", expected = "UDim" },
                    { class = "UIListLayout", property = "AbsoluteContentSize", expected = "Vector2" },
                    { class = "Sound", property = "SoundId", expected = "string" },
                    { class = "Animation", property = "AnimationId", expected = "string" },
                }
                for _, check in ipairs(checks) do
                    local ok_new, object = pcall(Instance.new, check.class)
                    if not ok_new or value_type(object) ~= "Instance" then
                        hard("instance_create_failed:" .. check.class, object)
                    else
                        local ok_read, value = pcall(read_member, object, check.property)
                        local actual = ok_read and value_type(value) or "read-error"
                        if not ok_read or actual ~= check.expected then
                            hard(
                                "property_type_mismatch:" .. check.class .. "." .. check.property,
                                { expected = check.expected, actual = actual }
                            )
                        else
                            pass("property_type_valid:" .. check.class .. "." .. check.property, actual)
                        end
                    end
                    destroy_instance(object)
                end
                local callback_checks = {
                    { class = "BindableFunction", property = "OnInvoke" },
                    { class = "RemoteFunction", property = "OnClientInvoke" },
                }
                local callback = function() return nil end
                for _, check in ipairs(callback_checks) do
                    local ok_new, object = pcall(Instance.new, check.class)
                    if not ok_new or value_type(object) ~= "Instance" then
                        hard("instance_create_failed:" .. check.class, object)
                    else
                        local ok_write = pcall(write_member, object, check.property, callback)
                        local ok_read, read_value = pcall(read_member, object, check.property)
                        if not ok_write then
                            hard("callback_property_write_failed:" .. check.class .. "." .. check.property, true)
                        elseif ok_read then
                            hard(
                                "callback_property_unexpectedly_readable:" .. check.class .. "." .. check.property,
                                value_type(read_value)
                            )
                        else
                            pass("callback_property_behavior_valid:" .. check.class .. "." .. check.property, true)
                        end
                    end
                    destroy_instance(object)
                end
            end
            local function check_enums()
                local enum_names = {
                    "KeyCode", "UserInputType", "UserInputState", "Material", "PartType",
                    "SurfaceType", "NormalId", "Axis", "Font", "FontWeight", "FontStyle",
                    "TextXAlignment", "TextYAlignment", "AutomaticSize", "FillDirection",
                    "HorizontalAlignment", "VerticalAlignment", "SortOrder", "EasingStyle",
                    "EasingDirection", "PlaybackState", "CameraType", "CameraMode",
                    "HumanoidStateType", "HumanoidRigType", "AnimationPriority",
                    "RaycastFilterType", "PathStatus", "PathWaypointAction", "ActuatorRelativeTo",
                    "OrientationAlignmentMode", "PositionAlignmentMode", "ScaleType",
                    "ResamplerMode", "ApplyStrokeMode", "LineJoinMode", "ScrollingDirection",
                    "ElasticBehavior", "ScreenInsets", "ZIndexBehavior", "CoreGuiType",
                    "MouseBehavior", "DevComputerMovementMode", "DevTouchMovementMode",
                    "ComputerCameraMovementMode", "TouchCameraMovementMode", "ChatVersion",
                    "CreatorType", "InfoType", "ProductPurchaseDecision",
                }
                if value_type(Enum) ~= "Enums" then
                    hard("enum_root_invalid", value_type(Enum))
                    return
                end
                for _, name in ipairs(enum_names) do
                    local ok_enum, enum_type = pcall(read_member, Enum, name)
                    if not ok_enum or value_type(enum_type) ~= "Enum" then
                        hard("enum_type_invalid:" .. name, value_type(enum_type))
                    elseif type(enum_type.GetEnumItems) ~= "function" then
                        hard("enum_getitems_missing:" .. name, type(enum_type.GetEnumItems))
                    else
                        local ok_items, items = pcall(enum_type.GetEnumItems, enum_type)
                        local first_item = nil
                        if ok_items and type(items) == "table" then
                            first_item = items[1]
                        end
                        if not ok_items then
                            hard("enum_getitems_failed:" .. name, items)
                        elseif value_type(first_item) ~= "EnumItem" then
                            hard("enum_first_item_invalid:" .. name, value_type(first_item))
                        elseif first_item.EnumType ~= enum_type then
                            hard("enum_item_wrong_owner:" .. name, true)
                        else
                            pass("enum_valid:" .. name, tostring(first_item))
                        end
                    end
                end
            end
            local function check_raw_environment_access()
                if type(rawget) ~= "function" then
                    hard("rawget_missing", type(rawget))
                    return
                end
                if type(rawset) ~= "function" then
                    hard("rawset_missing", type(rawset))
                    return
                end
                local env = _G
                if type(getgenv) == "function" then
                    local ok, result = pcall(getgenv)
                    if ok and type(result) == "table" then env = result end
                end
                if type(env) ~= "table" then
                    hard("raw_probe_environment_invalid", type(env))
                    return
                end
                local key = "\1_kf" .. tostring({})
                local marker = 25117
                local ok_write, write_error = pcall(rawset, env, key, marker)
                local ok_read, value = pcall(rawget, env, key)
                pcall(rawset, env, key, nil)
                if not ok_write then
                    hard("rawset_probe_failed", write_error)
                elseif not ok_read then
                    hard("rawget_probe_failed", value)
                elseif value ~= marker then
                    hard("raw_roundtrip_changed", value)
                else
                    pass("raw_roundtrip_valid", true)
                end
            end
            local function check_runtime_integrity()
                local pcall_id_a = tostring(pcall)
                local pcall_id_b = tostring(pcall)
                if pcall_id_a ~= pcall_id_b then
                    hard("pcall_identity_unstable", pcall_id_b)
                else
                    pass("pcall_identity_stable", true)
                end
                local xpcall_id_a = tostring(xpcall)
                local xpcall_id_b = tostring(xpcall)
                if xpcall_id_a ~= xpcall_id_b then
                    hard("xpcall_identity_unstable", xpcall_id_b)
                else
                    pass("xpcall_identity_stable", true)
                end
                local ok_cl, cl_val = pcall(at_closure_a)
                if not ok_cl or cl_val ~= 57005 then
                    hard("closure_a_value_wrong", cl_val)
                else
                    pass("closure_a_value_valid", true)
                end
                local ok_err, err_val = pcall(raise_named_probe_error)
                if ok_err or type(err_val) ~= "string"
                    or not string.find(err_val, "__ntt_probe__", 1, true) then
                    hard("named_error_not_preserved", err_val)
                else
                    pass("named_error_preserved", true)
                end
                local is_fn_hooked = rawget(_G, "isfunctionhooked")
                if type(is_fn_hooked) == "function" then
                    local natives = { pcall, xpcall, tostring, type,
                                      rawget, rawset, setmetatable, getmetatable }
                    for _, fn in ipairs(natives) do
                        if type(fn) == "function" and is_fn_hooked(fn) then
                            hard("native_function_hooked", tostring(fn))
                            break
                        end
                    end
                    pass("native_functions_not_hooked", true)
                else
                    pass("isfunctionhooked_absent", true)
                end
                local get_genv = rawget(_G, "getgenv")
                if type(get_genv) == "function" then
                    local ok_genv, genv = pcall(get_genv)
                    if ok_genv and type(genv) == "table" then
                        local probe_tbl = {}
                        genv[probe_tbl] = true
                        if rawget(genv, probe_tbl) ~= true then
                            hard("getgenv_rawset_roundtrip_failed", true)
                        else
                            pass("getgenv_rawset_roundtrip_valid", true)
                        end
                        genv[probe_tbl] = nil
                    else
                        soft("getgenv_call_failed", ok_genv)
                    end
                else
                    pass("getgenv_absent", true)
                end
                if type(debug) == "table" and type(debug.info) == "function" then
                    local ok_di, di_src = pcall(debug.info, 1, "s")
                    if not ok_di or type(di_src) ~= "string" then
                        hard("debug_info_returned_non_string", di_src)
                    else
                        pass("debug_info_source_valid", true)
                    end
                else
                    pass("debug_info_unavailable", true)
                end
                local ok_http, http_svc = pcall(function()
                    return game:GetService("HttpService")
                end)
                if ok_http and http_svc then
                    local ok_enc, enc_result = pcall(function()
                        return http_svc:JSONEncode({ a = 1 })
                    end)
                    if not ok_enc or type(enc_result) ~= "string" then
                        hard("jsonencode_returned_non_string", enc_result)
                    else
                        pass("jsonencode_valid", true)
                    end
                else
                    soft("http_service_unavailable", ok_http)
                end
                local ok_rs, rs = pcall(function() return game:GetService("RunService") end)
                if ok_rs and rs then
                    local ok_ic = pcall(function() rs:IsClient() end)
                    if not ok_ic then
                        hard("runservice_isclient_error", true)
                    else
                        pass("runservice_isclient_ok", true)
                    end
                end
                local probe_mt = setmetatable({}, {})
                local got_mt = getmetatable(probe_mt)
                if got_mt == nil then
                    hard("getmetatable_always_nil", true)
                else
                    pass("getmetatable_roundtrip_valid", true)
                end
                local clone_fn = rawget(_G, "clonefunction")
                if type(clone_fn) == "function" then
                    local ok_cl2, cloned = pcall(clone_fn, pcall)
                    if ok_cl2 and cloned == pcall then
                        soft("clonefunction_returned_same_ref", true)
                    else
                        pass("clonefunction_distinct", true)
                    end
                else
                    pass("clonefunction_absent", true)
                end
                local get_calling = rawget(_G, "getcallingscript")
                if type(get_calling) == "function" then
                    local ok_gc2, calling = pcall(get_calling)
                    if ok_gc2 and calling and typeof and typeof(script) == "Instance"
                        and calling ~= script then
                        soft("getcallingscript_mismatch", tostring(calling))
                    else
                        pass("getcallingscript_valid", true)
                    end
                else
                    pass("getcallingscript_absent", true)
                end
                local hook_fn = rawget(_G, "hookfunction")
                if type(hook_fn) == "function" then
                    pcall(hook_fn, at_closure_c, at_closure_d)
                    local ok_hk, hk_val = pcall(at_closure_c)
                    if ok_hk and hk_val == 2 then
                        hard("hookfunction_active", hk_val)
                    else
                        soft("hookfunction_present_but_ineffective", hk_val)
                    end
                else
                    pass("hookfunction_absent", true)
                end
                if not identity_self_test() then
                    hard("nan_identity_broken", true)
                else
                    pass("nan_identity_valid", true)
                end
                local fp = build_runtime_fingerprint(42)
                if type(fp) ~= "string" or #fp == 0 then
                    hard("runtime_fingerprint_empty", fp)
                else
                    pass("runtime_fingerprint_valid", true)
                end
                local s1 = encode_probe_string("antiTamper")
                local s2 = encode_probe_string("antiTamper")
                if s1 ~= s2 or type(s1) ~= "string" or #s1 == 0 then
                    hard("encode_probe_string_nondeterministic", s1)
                else
                    pass("encode_probe_string_valid", true)
                end
                do
                    local decoded = xor_decode(15, 105, 122, 97, 108, 123, 102, 96, 97)
                    if decoded ~= "function" then
                        hard("xor_decode_wrong_output", decoded)
                    else
                        pass("xor_decode_correct", true)
                    end
                end
                do
                    local a, b = 35, 8659
                    local step1 = _bxor(a, b)
                    local step2 = _bxor(step1, b)
                    if step2 ~= a then
                        hard("bxor_roundtrip_broken", { a = a, b = b, got = step2 })
                    else
                        pass("bxor_roundtrip_valid", true)
                    end
                    if _bxor(a, a) ~= 0 then
                        hard("bxor_self_cancel_broken", _bxor(a, a))
                    else
                        pass("bxor_self_cancel_valid", true)
                    end
                end
                do
                    local sentinel_global_key = "__at_sandbox_" .. tostring(math.random(1e9))
                    local sentinel_val = math.random(1e9)
                    _G[sentinel_global_key] = sentinel_val
                    local child_env = {}
                    local child_local_key = "__at_local_" .. tostring(math.random(1e9))
                    child_env[child_local_key] = true
                    setmetatable(child_env, {
                        __index = _G,
                        __newindex = function(t, k, v)
                            if rawget(_G, k) ~= nil then
                                rawset(t, k, v)
                            else
                                _G[k] = v
                            end
                        end,
                    })
                    local read_through = child_env[sentinel_global_key]
                    if read_through ~= sentinel_val then
                        hard("sandbox_env_read_through_broken", read_through)
                    else
                        pass("sandbox_env_read_through_valid", true)
                    end
                    local new_key = "__at_newkey_" .. tostring(math.random(1e9))
                    child_env[new_key] = 999
                    local in_G   = rawget(_G, new_key)
                    local in_child = rawget(child_env, new_key)
                    if in_G ~= 999 or in_child ~= nil then
                        hard("sandbox_env_new_write_wrong_target", { in_G = in_G, in_child = in_child })
                    else
                        pass("sandbox_env_new_write_valid", true)
                    end
                    child_env[child_local_key] = 777
                    local local_after = rawget(child_env, child_local_key)
                    if local_after ~= 777 then
                        hard("sandbox_env_local_write_broken", local_after)
                    else
                        pass("sandbox_env_local_write_valid", true)
                    end
                    _G[sentinel_global_key] = nil
                    _G[new_key] = nil
                    setmetatable(child_env, nil)
                end
                do
                    local function _coro_wrap(fn)
                        return function(...)
                            local thread = coroutine.create(fn)
                            local ok, result = coroutine.resume(thread, ...)
                            if not ok then
                                error(result, 2)
                            end
                        end
                    end
                    local probe_fn = function() end
                    for _ = 1, 198 do
                        probe_fn = _coro_wrap(probe_fn)
                    end
                    local ok_depth = pcall(probe_fn)
                    if not ok_depth then
                        soft("coroutine_stack_depth_too_shallow", 198)
                    else
                        pass("coroutine_stack_depth_ok", 198)
                    end
                end
                do
                    local _, err1 = pcall(function() error(1) end)
                    local _, err2 = pcall(function() error(2) end)
                    local v1 = string.match(tostring(err1), "%d+")
                    local v2 = string.match(tostring(err2), "%d+")
                    if not v1 or not v2 then
                        hard("error_passthrough_no_digits", { v1 = tostring(v1), v2 = tostring(v2) })
                    elseif v1 == v2 then
                        soft("error_passthrough_values_identical", v1)
                    else
                        pass("error_passthrough_distinct", { v1 = v1, v2 = v2 })
                    end
                end
                if type(debug) == "table" and type(debug.info) == "function" then
                    local function check_native_source(fn, name, is_critical)
                        if type(fn) ~= "function" then
                            soft("native_source_not_function:" .. name, type(fn))
                            return
                        end
                        local ok, src = pcall(debug.info, fn, "s")
                        if not ok then
                            soft("native_source_probe_failed:" .. name, src)
                            return
                        end
                        if src == "[C]" or src == nil then
                            pass("native_source_is_C:" .. name, true)
                        else
                            if is_critical then
                                hard("native_source_replaced:" .. name, src)
                            else
                                soft("native_source_wrapped:" .. name, src)
                            end
                        end
                    end
                    if not is_loadstring then
                        check_native_source(error,        "error",        true)
                        check_native_source(tostring,     "tostring",     true)
                        check_native_source(type,         "type",         true)
                        check_native_source(rawget,       "rawget",       true)
                        check_native_source(rawset,       "rawset",       true)
                        check_native_source(xpcall,       "xpcall",       false)
                        check_native_source(select,       "select",       false)
                        check_native_source(setmetatable, "setmetatable", false)
                        check_native_source(getmetatable, "getmetatable", false)
                        check_native_source(string.byte,  "string.byte",  false)
                        check_native_source(string.find,  "string.find",  false)
                        check_native_source(string.format,"string.format",false)
                        check_native_source(table.concat, "table.concat", false)
                        check_native_source(math.floor,   "math.floor",   false)
                    else
                    end
                else
                    pass("native_source_check_skipped_no_debug_info", true)
                end
            end
            check_forbidden_globals()
            check_known_executor_globals()
            check_debug_hook()
            check_line_consistency()
            check_coroutine_state()
            check_roblox_services()
            check_instance_properties()
            check_enums()
            check_raw_environment_access()
            check_runtime_integrity()
            local function check_advanced_environment()
                do
                    local ok, part = pcall(Instance.new, "Part")
                    if ok and part then
                        local checks = {
                            { typeof(part.Size)       == "Vector3",  "part_size_typeof" },
                            { typeof(part.CFrame)     == "CFrame",   "part_cframe_typeof" },
                            { typeof(part.Color)      == "Color3",   "part_color_typeof" },
                            { typeof(part.BrickColor) == "BrickColor","part_brickcolor_typeof" },
                            { typeof(part.Material)   == "EnumItem", "part_material_typeof" },
                        }
                        for _, c in ipairs(checks) do
                            if c[1] then pass(c[2], true) else hard(c[2], false) end
                        end
                        part:Destroy()
                    else
                        soft("instance_new_part_failed", ok)
                    end
                    local ok2, snd = pcall(Instance.new, "Sound")
                    if ok2 and snd then
                        local can_write = pcall(function() snd.PlaybackLoudness = 69 end)
                        if can_write then
                            hard("playbackloudness_writable", true)
                        else
                            pass("playbackloudness_readonly", true)
                        end
                        snd:Destroy()
                    end
                    local ok3, tb = pcall(Instance.new, "TextBox")
                    if ok3 and tb then
                        local can_write = pcall(function() tb.TextBounds = Vector2.new(67, 67) end)
                        if can_write then
                            hard("textbounds_writable", true)
                        else
                            pass("textbounds_readonly", true)
                        end
                        tb:Destroy()
                    end
                    local ok4, snd2 = pcall(Instance.new, "Sound")
                    if ok4 and snd2 then
                        snd2.Name = "g"
                        local before = tostring(snd2)
                        snd2.Name = "gg"
                        local after = tostring(snd2)
                        if before == after then
                            hard("instance_name_change_not_reflected", before)
                        else
                            pass("instance_name_change_reflected", true)
                        end
                        snd2:Destroy()
                    end
                    local fake_ok = pcall(function() Instance.new("FakeClass_AT_99999") end)
                    if fake_ok then
                        hard("instance_new_accepts_fake_class", true)
                    else
                        pass("instance_new_rejects_fake_class", true)
                    end
                    local fake_svc = pcall(function() game:GetService("FakeService_AT_99999") end)
                    if fake_svc then
                        hard("getservice_accepts_fake_service", true)
                    else
                        pass("getservice_rejects_fake_service", true)
                    end
                end
                do
                    local ok, result = pcall(rawequal, game, workspace.Parent)
                    if ok then
                        if result then pass("game_is_workspace_parent", true)
                        else hard("game_not_workspace_parent", true) end
                    end
                    -- Enum.Material.Plastic.Parent throws in Luau — removed
                    local locked = {
                        { game,                          "game" },
                        { workspace,                     "workspace" },
                        { game:GetService("Players"),    "Players" },
                        { game:GetService("RunService"), "RunService" },
                    }
                    for _, pair in ipairs(locked) do
                        local inst, name = pair[1], pair[2]
                        local ok3, mt = pcall(getmetatable, inst)
                        if ok3 then
                            if mt == "The metatable is locked" then
                                pass("metatable_locked:" .. name, true)
                            else
                                hard("metatable_not_locked:" .. name, tostring(mt))
                            end
                        end
                    end
                    local roblox_types = {
                        { CFrame.new(),    "CFrame"    },
                        { Vector3.new(),   "Vector3"   },
                        { UDim2.new(),     "UDim2"     },
                        { Color3.new(),    "Color3"    },
                    }
                    for _, pair in ipairs(roblox_types) do
                        local val, expected = pair[1], pair[2]
                        if typeof(val) == type(val) then
                            hard("typeof_equals_type:" .. expected, type(val))
                        else
                            pass("typeof_differs_from_type:" .. expected, true)
                        end
                    end
                    local ok4, folder = pcall(Instance.new, "Folder")
                    if ok4 and folder then
                        if type(folder) ~= "userdata" then
                            hard("instance_type_not_userdata", type(folder))
                        else
                            pass("instance_type_is_userdata", true)
                        end
                        folder:Destroy()
                    end
                    local libs = {
                        { math,      "math" },
                        { string,    "string" },
                        { table,     "table" },
                        { coroutine, "coroutine" },
                        { bit32,     "bit32" },
                        { task,      "task" },
                        { os,        "os" },
                    }
                    for _, pair in ipairs(libs) do
                        local lib, name = pair[1], pair[2]
                        if type(lib) == "table" then
                            if not table.isfrozen(lib) then
                                soft("stdlib_not_frozen:" .. name, true)
                            else
                                pass("stdlib_frozen:" .. name, true)
                            end
                            local write_ok = pcall(function() lib["__at_probe"] = 1 end)
                            if write_ok then
                                soft("stdlib_writable:" .. name, true)
                            end
                        end
                    end
                    local str_mt = getmetatable("")
                    if type(str_mt) == "table" then
                        if not table.isfrozen(str_mt) then
                            soft("string_metatable_not_frozen", true)
                        else
                            pass("string_metatable_frozen", true)
                        end
                    end
                    local ran = false
                    local ok5, co = pcall(function()
                        return task.spawn(function() ran = true end)
                    end)
                    if ok5 then
                        if type(co) ~= "thread" then
                            hard("task_spawn_not_thread", type(co))
                        elseif not ran then
                            hard("task_spawn_not_immediate", true)
                        else
                            pass("task_spawn_valid", true)
                        end
                    end
                    local iter_ok = pcall(function() for _ in game do end end)
                    if iter_ok then
                        hard("game_is_iterable", true)
                    else
                        pass("game_not_iterable", true)
                    end
                    local _, game_err = pcall(function() game() end)
                    if type(game_err) == "string"
                        and game_err:find("attempt to call a Instance value", 1, true) then
                        pass("game_call_error_message_valid", true)
                    else
                        hard("game_call_error_message_wrong", tostring(game_err))
                    end
                    local clone_ok = pcall(game.Clone, game)
                    if clone_ok then
                        hard("game_clone_succeeded", true)
                    else
                        pass("game_clone_errors", true)
                    end
                    local ok6 = pcall(function()
                        assert(game.Close == game.Close, "signal not stable")
                    end)
                    if ok6 then pass("game_close_signal_stable", true)
                    else hard("game_close_signal_unstable", true) end
                    local ok7, loaded = pcall(function() return game:IsLoaded() end)
                    if ok7 then
                        if loaded then pass("game_is_loaded", true)
                        else soft("game_is_not_loaded", true) end
                    end
                    local ok8, gid = pcall(function() return game.GameId end)
                    if ok8 then
                        if type(gid) ~= "number" then
                            hard("gameid_not_number", type(gid))
                        elseif gid == 0 then
                            soft("gameid_is_zero", true)
                        else
                            pass("gameid_valid", gid)
                        end
                    end
                    local ok9, pid = pcall(function() return game.PlaceId end)
                    if ok8 and ok9 and gid and pid then
                        if gid == pid then
                            soft("placeid_equals_gameid", true)
                        else
                            pass("placeid_differs_from_gameid", true)
                        end
                    end
                    local ok10, cg = pcall(function() return game:GetService("CoreGui") end)
                    if ok10 and cg then
                        local has_sg = cg:FindFirstChildOfClass("ScreenGui") ~= nil
                        if has_sg then pass("coregui_has_screengui", true)
                        else soft("coregui_no_screengui", true) end
                    end
                    if rawget(_G, "getrawmetatable") ~= nil then
                        hard("getrawmetatable_present", true)
                    else
                        pass("getrawmetatable_absent", true)
                    end
                end
                do
                    local ok, nc = pcall(function() return game:GetService("NetworkClient") end)
                    if ok and nc then
                        if nc:FindFirstChild("ClientReplicator") then
                            pass("networkclient_has_replicator", true)
                        else
                            hard("networkclient_missing_replicator", true)
                        end
                    else
                        soft("networkclient_unavailable", ok)
                    end
                    local ok2, chat = pcall(function() return game:GetService("Chat") end)
                    if ok2 and chat and chat.Parent then
                        if chat.Parent.Name == "Ugc" then
                            pass("chat_parent_ugc", true)
                        else
                            hard("chat_parent_not_ugc", chat.Parent.Name)
                        end
                    end
                    local ok3, hs = pcall(function() return game:GetService("HttpService") end)
                    if ok3 and hs then
                        local ok_g, g1 = pcall(function() return hs:GenerateGUID(false) end)
                        local _, g2   = pcall(function() return hs:GenerateGUID(false) end)
                        if ok_g and g1 then
                            if #g1 ~= 36 then
                                hard("guid_length_wrong", #g1)
                            elseif g1:sub(9,9) ~= "-" then
                                hard("guid_format_wrong", g1)
                            elseif g1 == g2 then
                                hard("guid_not_random", g1)
                            else
                                pass("guid_valid", true)
                            end
                        end
                    end
                    local ok4, fps = pcall(function() return workspace:GetRealPhysicsFPS() end)
                    if ok4 then
                        if type(fps) ~= "number" or fps <= 0 or fps > 300 then
                            hard("physics_fps_invalid", fps)
                        else
                            pass("physics_fps_valid", fps)
                        end
                    else
                        soft("physics_fps_unavailable", ok4)
                    end
                    local ok6, gid  = pcall(function() return game:GetDebugId(0) end)
                    local ok7, wid  = pcall(function() return workspace:GetDebugId(0) end)
                    local ok8, plid = pcall(function() return game:GetService("Players"):GetDebugId(0) end)
                    if ok6 and ok7 and ok8 then
                        if type(gid) ~= "string" or #gid == 0 then
                            hard("debugid_game_invalid", tostring(gid))
                        elseif gid == wid or gid == plid or wid == plid then
                            hard("debugid_not_unique", true)
                        else
                            pass("debugid_unique", true)
                        end
                    end
                    local ok9 = pcall(function()
                        local ok_settings, ql = pcall(function()
                            return settings().Rendering.QualityLevel
                        end)
                        if not ok_settings then
                            soft("quality_level_settings_unavailable", true)
                            return
                        end
                        assert(typeof(ql) == "EnumItem", "not EnumItem")
                        local found = false
                        for _, item in ipairs(Enum.QualityLevel:GetEnumItems()) do
                            if item == ql then found = true break end
                        end
                        assert(found, "not in QualityLevel enum")
                    end)
                    if ok9 then pass("quality_level_valid", true)
                    else soft("quality_level_invalid", true) end
                    local ok10 = pcall(function()
                        local es = game:GetService("EncodingService")
                        local b = buffer.create(7)
                        buffer.writestring(b, 0, "at_test")
                        local c = es:CompressBuffer(b, Enum.CompressionAlgorithm.Zstd, 1)
                        local d = es:DecompressBuffer(c, Enum.CompressionAlgorithm.Zstd)
                        assert(buffer.readstring(d, 0, 7) == "at_test", "mismatch")
                    end)
                    if ok10 then pass("encoding_service_roundtrip", true)
                    else hard("encoding_service_roundtrip_failed", true) end
                    local ok11, t1 = pcall(function() return workspace:GetServerTimeNow() end)
                    if ok11 and type(t1) == "number" then
                        task.wait(0.05)
                        local _, t2 = pcall(function() return workspace:GetServerTimeNow() end)
                        if type(t2) == "number" and t2 > t1 then
                            pass("server_time_advances", true)
                        else
                            hard("server_time_not_advancing", t2)
                        end
                    end
                    local ok12, dgt1 = pcall(function() return workspace.DistributedGameTime end)
                    if ok12 and type(dgt1) == "number" then
                        task.wait(0.1)
                        local _, dgt2 = pcall(function() return workspace.DistributedGameTime end)
                        if type(dgt2) == "number" and dgt2 > dgt1 then
                            pass("distributed_game_time_advances", true)
                        else
                            hard("distributed_game_time_static", dgt2)
                        end
                    end
                    local ok13, rs = pcall(function() return game:GetService("RunService") end)
                    if ok13 and rs then
                        local dts, count = {}, 0
                        local conn
                        local ok14 = pcall(function()
                            conn = rs.Heartbeat:Connect(function(dt)
                                count = count + 1
                                dts[count] = dt
                                if count >= 5 then conn:Disconnect() end
                            end)
                        end)
                        if ok14 then
                            local t0 = os.clock()
                            while count < 5 and (os.clock() - t0) < 5 do task.wait() end
                            if count >= 5 then
                                local bad = false
                                local same = true
                                for i, dt in ipairs(dts) do
                                    if type(dt) ~= "number" or dt <= 0 or dt > 1 then
                                        bad = true
                                    end
                                    if i > 1 and dt ~= dts[1] then same = false end
                                end
                                if bad then hard("heartbeat_delta_invalid", true)
                                elseif same then hard("heartbeat_deltas_all_same", true)
                                else pass("heartbeat_deltas_valid", true) end
                            end
                        end
                    end
                    local ok15 = pcall(function()
                        local cs = game:GetService("CaptureService")
                        local conn2 = cs.CaptureBegan:Connect(function() end)
                        assert(typeof(conn2) == "RBXScriptConnection", "not connection")
                        conn2:Disconnect()
                        assert(conn2.Connected == false, "still connected after disconnect")
                    end)
                    if ok15 then pass("connection_disconnect_valid", true)
                    else soft("connection_disconnect_invalid", true) end
                    local ok16 = pcall(function()
                        local cas = game:GetService("ContextActionService")
                        cas:BindAction("__at_test", function() end, false, Enum.KeyCode.F)
                        local info = cas:GetAllBoundActionInfo()
                        assert(info["__at_test"] ~= nil, "action not found")
                        assert(info["__at_test"].inputTypes[1] == Enum.KeyCode.F, "wrong key")
                        cas:UnbindAction("__at_test")
                    end)
                    if ok16 then pass("context_action_roundtrip", true)
                    else soft("context_action_roundtrip_failed", true) end
                    local ok17 = pcall(function()
                        local op = OverlapParams.new()
                        assert(typeof(op) == "OverlapParams", "wrong type")
                        assert(op.MaxParts == 0, "MaxParts not 0: " .. tostring(op.MaxParts))
                        assert(op.FilterType == Enum.RaycastFilterType.Exclude,
                            "FilterType wrong: " .. tostring(op.FilterType))
                    end)
                    if ok17 then pass("overlapparams_defaults_valid", true)
                    else hard("overlapparams_defaults_wrong", true) end
                    local ok18 = pcall(function()
                        local ds = game:GetService("DataStoreService")
                        local bad_ok = pcall(ds.GetDataStore, ds, "invalid//name@chars", "scope")
                        assert(not bad_ok, "invalid DataStore name was accepted")
                    end)
                    if ok18 then pass("datastore_invalid_name_rejected", true)
                    else soft("datastore_invalid_name_check_failed", true) end
                end
                do
                    local sum = 0
                    for i = 1, 1000000 do sum = sum + i end
                    if sum ~= 500000500000 then
                        hard("integer_sum_wrong", sum)
                    else
                        pass("integer_sum_correct", true)
                    end
                    local base = Vector3.one
                    local ok = true
                    for i = 1, 5 do
                        local n = math.random(1, 67)
                        if base * n ~= Vector3.new(n, n, n) then ok = false break end
                    end
                    if ok then pass("vector3_one_math_valid", true)
                    else hard("vector3_one_math_broken", true) end
                    local rx = CFrame.Angles(math.rad(90), 0, 0)
                    local ry = CFrame.Angles(0, math.rad(90), 0)
                    local diff = ((rx * ry).LookVector - (ry * rx).LookVector).Magnitude
                    if diff > 1e-4 then pass("cframe_noncommutative", true)
                    else hard("cframe_commutative_broken", diff) end
                    local log_result = math.log(100, 10)
                    if math.abs(log_result - 2) > 1e-5 then
                        hard("math_log_wrong", log_result)
                    else
                        pass("math_log_correct", true)
                    end
                    local ok2, err2 = pcall(math.log)
                    if not ok2 and type(err2) == "string" and err2:lower():find("missing") then
                        pass("math_log_missing_arg_error", true)
                    else
                        soft("math_log_missing_arg_not_errored", tostring(err2))
                    end
                    local ok3 = pcall(function()
                        local t = {1, 2, 3}
                        table.freeze(t)
                        assert(table.isfrozen(t), "isfrozen returned false")
                        local write_ok = pcall(function() t[1] = 99 end)
                        assert(not write_ok, "write to frozen table succeeded")
                        assert(t[1] == 1, "frozen value changed")
                    end)
                    if ok3 then pass("table_freeze_valid", true)
                    else hard("table_freeze_broken", true) end
                    local ok4 = pcall(function()
                        local buf = buffer.create(8)
                        buffer.writeu32(buf, 0, 0xDEADBEEF)
                        assert(buffer.readu32(buf, 0) == 0xDEADBEEF, "buffer roundtrip failed")
                    end)
                    if ok4 then pass("buffer_u32_roundtrip", true)
                    else hard("buffer_u32_roundtrip_failed", true) end
                    local ok5 = pcall(function()
                        local bc = BrickColor.new("Bright red")
                        local c3 = bc.Color
                        local rc = BrickColor.new(Color3.new(c3.R, c3.G, c3.B))
                        assert(rc.Number == bc.Number and type(bc.Number) == "number" and bc.Number > 0,
                            "BrickColor roundtrip failed")
                    end)
                    if ok5 then pass("brickcolor_roundtrip", true)
                    else hard("brickcolor_roundtrip_failed", true) end
                end
                do
                    local ok, tb = pcall(debug.traceback)
                    if ok and type(tb) == "string" and #tb > 10 then
                        local lower_tb = tb:lower()
                        local sandbox_words = {
                            "sandbox", "hook", "intercept", "mock", "proxy",
                            "virtual_env", "decompil", "emulat", "simulat",
                            "fake_", "getupval", "hookfunc", "replaceclos",
                            "newcclos", "restorefunction",
                        }
                        local found_word = nil
                        for _, word in ipairs(sandbox_words) do
                            if lower_tb:find(word, 1, true) then
                                found_word = word
                                break
                            end
                        end
                        if found_word then
                            hard("traceback_contains_sandbox_word", found_word)
                        else
                            pass("traceback_clean", true)
                        end
                        local checksum = 0
                        for i = 1, #tb do
                            checksum = (checksum + string.byte(tb, i) * i) % 2147483647
                        end
                        if checksum == 0 then
                            soft("traceback_checksum_zero", true)
                        else
                            pass("traceback_checksum_nonzero", true)
                        end
                    else
                        soft("traceback_too_short_or_failed", ok)
                    end
                    if type(debug) == "table" and type(debug.getupvalue) == "function" then
                        local natives_to_check = {
                            { pcall,        "pcall" },
                            { string.find,  "string.find" },
                        }
                        for _, pair in ipairs(natives_to_check) do
                            local fn, name = pair[1], pair[2]
                            local ok2, upname = pcall(debug.getupvalue, fn, 1)
                            if ok2 and upname ~= nil then
                                hard("native_has_upvalue:" .. name, upname)
                            else
                                pass("native_no_upvalue:" .. name, true)
                            end
                        end
                    else
                        pass("debug_getupvalue_unavailable", true)
                    end
                    local sandbox_keys = {
                        "__sandbox", "__mock", "__wrapped", "__intercept",
                        "_real_env", "__HOOKED__",
                    }
                    local found_marker = false
                    for _, key in ipairs(sandbox_keys) do
                        if rawget(_G, key) ~= nil then
                            hard("sandbox_marker_present:" .. key, true)
                            found_marker = true
                        end
                    end
                    if not found_marker then
                        pass("sandbox_markers_absent", true)
                    end
                end
                do
                    local ok, part = pcall(Instance.new, "Part")
                    if ok and part then
                        part.Size = Vector3.new(2, 2, 2)
                        local ok2, mass = pcall(function() return part:GetMass() end)
                        if ok2 then
                            if math.abs(mass - 5.6) > 0.1 then
                                hard("part_mass_wrong", mass)
                            else
                                pass("part_mass_valid", mass)
                            end
                        end
                        part:Destroy()
                    end
                end
                do
                    if type(debug) == "table" and type(debug.getinfo) == "function" then
                        local function hash_fn(fn)
                            local ok, info = pcall(debug.getinfo, fn)
                            if not ok or not info then return 0 end
                            local s = tostring(fn)
                                .. tostring(info.source or "")
                                .. tostring(info.linedefined or 0)
                            local h = 0
                            for i = 1, #s do
                                h = _bxor(
                                    _band(h * 33, 0xFFFFFFFF) + string.byte(s, i),
                                    _band(h, 0xFFFFFFFF)
                                )
                            end
                            return h
                        end
                        local probe_fn = function() end
                        local h1 = hash_fn(probe_fn)
                        task.wait(0.001)
                        local h2 = hash_fn(probe_fn)
                        if h1 ~= h2 then
                            hard("debug_info_hash_unstable", { h1 = h1, h2 = h2 })
                        else
                            pass("debug_info_hash_stable", true)
                        end
                    else
                        pass("debug_getinfo_unavailable_skip_hash", true)
                    end
                end
                do
                    local co = coroutine.create(function()
                        coroutine.yield(10)
                        coroutine.yield(20)
                    end)
                    local _, v1 = coroutine.resume(co)
                    local _, v2 = coroutine.resume(co)
                    if v1 ~= 10 or v2 ~= 20 then
                        hard("coroutine_yield_value_wrong", {v1=v1, v2=v2})
                    else
                        pass("coroutine_yield_value_correct", true)
                    end
                    local new_co = coroutine.create(function() end)
                    if coroutine.status(new_co) ~= "suspended" then
                        hard("coroutine_status_new_not_suspended",
                            coroutine.status(new_co))
                    else
                        pass("coroutine_status_new_suspended", true)
                    end
                    if not coroutine.isyieldable() then
                        hard("coroutine_not_yieldable", true)
                    else
                        pass("coroutine_isyieldable", true)
                    end
                    local mt = setmetatable({}, {
                        __index = function(_, k) return k .. "ok" end
                    })
                    if mt["env"] ~= "envok" then
                        hard("metamethod_index_fn_wrong", mt["env"])
                    else
                        pass("metamethod_index_fn_correct", true)
                    end
                    local coder = setmetatable({}, {__newindex = function() end})
                    rawset(coder, "val", 42)
                    if rawget(coder, "val") ~= 42 then
                        hard("rawset_rawget_bypass_wrong", rawget(coder,"val"))
                    else
                        pass("rawset_rawget_bypass_correct", true)
                    end
                    local prim_checks = {
                        {nil,          "nil"},
                        {true,         "boolean"},
                        {1,            "number"},
                        {function()end,"function"},
                    }
                    for _, pair in ipairs(prim_checks) do
                        local mt2 = getmetatable(pair[1])
                        if mt2 ~= nil then
                            hard("getmetatable_primitive_not_nil:" .. pair[2], tostring(mt2))
                        else
                            pass("getmetatable_primitive_nil:" .. pair[2], true)
                        end
                    end
                    local plain = {1,2,3,4,5}
                    if rawlen(plain) ~= #plain then
                        hard("rawlen_differs_from_length",
                            {rawlen=rawlen(plain), hash=#plain})
                    else
                        pass("rawlen_equals_length", true)
                    end
                end
                do
                    local ok_part, part = pcall(Instance.new, "Part")
                    if ok_part and part then
                        local sig = part:GetPropertyChangedSignal("Name")
                        if typeof(sig) ~= "RBXScriptSignal" then
                            hard("signal_not_RBXScriptSignal", typeof(sig))
                        else
                            pass("signal_is_RBXScriptSignal", true)
                        end
                        local con = sig:Connect(function() end)
                        if typeof(con) ~= "RBXScriptConnection" then
                            hard("connection_not_RBXScriptConnection", typeof(con))
                        else
                            pass("connection_is_RBXScriptConnection", true)
                        end
                        if con.Connected ~= true then
                            hard("connection_not_connected_after_connect", con.Connected)
                        else
                            pass("connection_connected_after_connect", true)
                        end
                        con:Disconnect()
                        if con.Connected ~= false then
                            hard("connection_still_connected_after_disconnect", con.Connected)
                        else
                            pass("connection_disconnected", true)
                        end
                        local c1 = sig:Connect(function() end)
                        local c2 = sig:Connect(function() end)
                        if c1 == c2 then
                            hard("two_connections_same_ref", true)
                        else
                            pass("two_connections_differ", true)
                        end
                        c1:Disconnect()
                        if c2.Connected ~= true then
                            hard("c2_affected_by_c1_disconnect", c2.Connected)
                        else
                            pass("independent_disconnects", true)
                        end
                        c2:Disconnect()
                        local ok_once, c3 = pcall(function() return sig:Once(function() end) end)
                        if ok_once then
                            if typeof(c3) ~= "RBXScriptConnection" then
                                hard("once_not_connection", typeof(c3))
                            else
                                pass("once_returns_connection", true)
                            end
                            c3:Disconnect()
                        end
                        local fired = false
                        local fc = sig:Connect(function() fired = true end)
                        part.Name = "__at_signal_test"
                        task.wait(0.05)
                        fc:Disconnect()
                        if not fired then
                            hard("signal_did_not_fire_on_change", false)
                        else
                            pass("signal_fires_on_change", true)
                        end
                        part:Destroy()
                    else
                        soft("signal_test_part_failed", ok_part)
                    end
                end
                do
                    local bit_checks = {
                        {bit32.bnot(0),               4294967295, "bnot(0)"},
                        {bit32.bor(4,2),              6,          "bor(4,2)"},
                        {bit32.lrotate(1,2),          4,          "lrotate(1,2)"},
                        {bit32.rrotate(4,2),          1,          "rrotate(4,2)"},
                        {bit32.extract(7,1,2),        3,          "extract(7,1,2)"},
                        {bit32.replace(0x0,0xF,0,4),  0xF,        "replace"},
                        {bit32.extract(0xFF,0,4),     0xF,        "extract(0xFF,0,4)"},
                        {bit32.countlz(0x00FFFFFF),   8,          "countlz"},
                        {bit32.countrz(0xFFFFFF00),   8,          "countrz"},
                    }
                    for _, c in ipairs(bit_checks) do
                        if c[1] ~= c[2] then
                            hard("bit32_" .. c[3] .. "_wrong", c[1])
                        else
                            pass("bit32_" .. c[3] .. "_ok", true)
                        end
                    end
                    local math_checks = {
                        {math.ldexp(0.5,1),    1,    "ldexp"},
                        {math.frexp(1),        0.5,  "frexp"},
                        {math.modf(3.5),       3,    "modf"},
                        {math.fmod(10,3),      1,    "fmod"},
                        {math.abs(math.rad(180)-math.pi) < 1e-9 and 1 or 0, 1, "rad"},
                        {math.abs(math.deg(math.pi)-180) < 1e-9 and 1 or 0, 1, "deg"},
                    }
                    for _, c in ipairs(math_checks) do
                        if c[1] ~= c[2] then
                            hard("math_" .. c[3] .. "_wrong", c[1])
                        else
                            pass("math_" .. c[3] .. "_ok", true)
                        end
                    end
                    local ok_pk, packed = pcall(string.pack, "b", 100)
                    if ok_pk then
                        if packed ~= string.char(100) then
                            hard("string_pack_wrong", packed)
                        else
                            pass("string_pack_ok", true)
                        end
                        local ok_upk, val = pcall(string.unpack, "b", packed)
                        if ok_upk and val == 100 then
                            pass("string_unpack_ok", true)
                        else
                            hard("string_unpack_wrong", val)
                        end
                    end
                    local utf8_checks = {
                        {utf8.char(104),             "h",   "char(104)"},
                        {tostring(utf8.len("abc")),  "3",   "len(abc)"},
                        {tostring(utf8.codepoint("a")), "97", "codepoint(a)"},
                        {utf8.nfcnormalize("a"),     "a",   "nfcnormalize"},
                        {utf8.nfdnormalize("a"),     "a",   "nfdnormalize"},
                    }
                    for _, c in ipairs(utf8_checks) do
                        if c[1] ~= c[2] then
                            hard("utf8_" .. c[3] .. "_wrong", c[1])
                        else
                            pass("utf8_" .. c[3] .. "_ok", true)
                        end
                    end
                    local type_checks = {
                        {function() return DateTime.now() end,                     "DateTime"},
                        {function() return Font.fromEnum(Enum.Font.Arial) end,     "Font"},
                        {function() return Rect.new(0,0,10,10) end,                "Rect"},
                        {function() return NumberRange.new(1,2) end,               "NumberRange"},
                        {function() return PhysicalProperties.new(1,0.5,0.5) end, "PhysicalProperties"},
                    }
                    for _, pair in ipairs(type_checks) do
                        local ok_t, val = pcall(pair[1])
                        if ok_t then
                            if typeof(val) ~= pair[2] then
                                hard("typeof_" .. pair[2] .. "_wrong", typeof(val))
                            else
                                pass("typeof_" .. pair[2] .. "_ok", true)
                            end
                        else
                            soft("typeof_" .. pair[2] .. "_unavailable", val)
                        end
                    end
                    if type(shared) ~= "table" then
                        hard("shared_not_table", type(shared))
                    else
                        pass("shared_is_table", true)
                    end
                    local ok_dt, dt = pcall(function() return os.date("*t") end)
                    if ok_dt and type(dt) == "table" then
                        if type(dt.year) ~= "number" or dt.year < 2025 then
                            hard("os_date_year_wrong", dt.year)
                        else
                            pass("os_date_year_ok", dt.year)
                        end
                    end
                end
                do
                    local _, err1 = pcall(function() return game.NotAValidPropertyAT end)
                    if type(err1)=="string" and err1:find("is not a valid member of",1,true) then
                        pass("error_msg_invalid_property", true)
                    else
                        hard("error_msg_invalid_property_wrong", tostring(err1))
                    end
                    local _, err2 = pcall(function() return workspace:GetSomethingAT() end)
                    if type(err2)=="string" and err2:find("is not a valid member of Workspace",1,true) then
                        pass("error_msg_invalid_method", true)
                    else
                        hard("error_msg_invalid_method_wrong", tostring(err2))
                    end
                    local _, err3 = pcall(function() return string.len(nil) end)
                    if type(err3)=="string" and err3:find("invalid argument #1",1,true) then
                        pass("error_msg_string_len_nil", true)
                    else
                        hard("error_msg_string_len_nil_wrong", tostring(err3))
                    end
                    local _, err4 = pcall(function() return table.concat(true) end)
                    if type(err4)=="string" and err4:find("invalid argument #1",1,true) then
                        pass("error_msg_table_concat_bool", true)
                    else
                        hard("error_msg_table_concat_bool_wrong", tostring(err4))
                    end
                    local ok_ra, part_ra = pcall(Instance.new, "Part")
                    if ok_ra and part_ra then
                        local write_ra = pcall(function() part_ra.ReceiveAge = 1 end)
                        if write_ra then
                            hard("part_receiveage_writable", true)
                        else
                            pass("part_receiveage_readonly", true)
                        end
                        part_ra:Destroy()
                    end
                    if type(debug) == "table" and type(debug.info) == "function" then
                        local function lua_fn() end
                        local ok_di, src = pcall(debug.info, lua_fn, "s")
                        if ok_di then
                            if src == "[C]" then
                                hard("lua_fn_reported_as_C", src)
                            else
                                pass("lua_fn_not_C", true)
                            end
                        end
                        local ok_a, arity, isvararg = pcall(debug.info, lua_fn, "a")
                        if ok_a then
                            if arity ~= 0 then
                                hard("debug_info_arity_wrong", arity)
                            elseif isvararg ~= false then
                                hard("debug_info_vararg_wrong", isvararg)
                            else
                                pass("debug_info_arity_vararg_ok", true)
                            end
                        end
                        local depth = 0
                        string.gsub("a", ".", function()
                            local i = 1
                            while debug.info(i, "f") do
                                depth = i; i = i + 1
                            end
                        end)
                        if depth >= 4 and depth <= 8 then
                            pass("gsub_stack_depth_ok", depth)
                        else
                            hard("gsub_stack_depth_wrong", depth)
                        end
                    end
                    local ok_lp, lp = pcall(function()
                        return game:GetService("Players").LocalPlayer
                    end)
                    if ok_lp and lp then
                        local ok_mt, mtype = pcall(function() return lp.MembershipType end)
                        if ok_mt then
                            local valid = mtype == Enum.MembershipType.None
                                       or mtype == Enum.MembershipType.Premium
                            if not valid then
                                hard("membership_type_invalid", tostring(mtype))
                            else
                                pass("membership_type_valid", true)
                            end
                        end
                    end
                    local bulk_parts, bulk_targets = {}, {}
                    for i = 1, 5 do
                        local bp = Instance.new("Part")
                        bp.Anchored = true
                        bp.Parent = workspace
                        bulk_parts[i] = bp
                        bulk_targets[i] = CFrame.new(i * 10, 50, 0)
                    end
                    local ok_bulk = pcall(workspace.BulkMoveTo, workspace,
                        bulk_parts, bulk_targets, Enum.BulkMoveMode.FireCFrameChanged)
                    if ok_bulk then
                        local all_ok = true
                        for i, bp in ipairs(bulk_parts) do
                            if (bp.CFrame.Position - bulk_targets[i].Position).Magnitude > 0.01 then
                                all_ok = false
                            end
                        end
                        if all_ok then pass("bulkmoveto_correct", true)
                        else hard("bulkmoveto_positions_wrong", true) end
                    else
                        soft("bulkmoveto_unavailable", true)
                    end
                    for _, bp in ipairs(bulk_parts) do bp:Destroy() end
                end
                do
                    local ok_lt, lt = pcall(function() return game:GetService("Lighting") end)
                    if ok_lt and lt then
                        local orig = lt.ClockTime
                        lt.ClockTime = 12
                        local read = lt.ClockTime
                        lt.ClockTime = orig
                        if read ~= 12 then
                            hard("lighting_clocktime_roundtrip_wrong", read)
                        else
                            pass("lighting_clocktime_roundtrip_ok", true)
                        end
                        local ok2, mins = pcall(lt.GetMinutesAfterMidnight, lt)
                        if ok2 and typeof(mins) ~= "number" then
                            hard("lighting_minutes_not_number", typeof(mins))
                        else
                            pass("lighting_minutes_number_ok", true)
                        end
                    end
                    local ok_ss, ss = pcall(function() return game:GetService("SoundService") end)
                    if ok_ss and ss then
                        if typeof(ss.AmbientReverb) ~= "EnumItem" then
                            hard("soundservice_ambientreverb_not_enumitem", typeof(ss.AmbientReverb))
                        else
                            pass("soundservice_ambientreverb_enumitem", true)
                        end
                        if typeof(ss.RespectFilteringEnabled) ~= "boolean" then
                            hard("soundservice_rfe_not_boolean", typeof(ss.RespectFilteringEnabled))
                        else
                            pass("soundservice_rfe_boolean", true)
                        end
                    end
                    local ok_gfn = pcall(function()
                        local p = Instance.new("Part", workspace)
                        local n = p:GetFullName()
                        p:Destroy()
                        assert(typeof(n) == "string" and n:find("Workspace"),
                            "GetFullName wrong: " .. tostring(n))
                    end)
                    if ok_gfn then pass("getfullname_contains_workspace", true)
                    else hard("getfullname_wrong", true) end
                    local ok_rp = pcall(function()
                        local rp = RaycastParams.new()
                        assert(rp.IgnoreWater == false, "IgnoreWater not false")
                        rp.CollisionGroup = "Default"
                        assert(rp.CollisionGroup == "Default", "CollisionGroup roundtrip failed")
                    end)
                    if ok_rp then pass("raycastparams_defaults_ok", true)
                    else hard("raycastparams_defaults_wrong", true) end
                    local ok_r3, r3 = pcall(function()
                        return Region3int16.new(Vector3int16.new(0,0,0), Vector3int16.new(10,10,10))
                    end)
                    if ok_r3 and typeof(r3) == "Region3int16" then
                        pass("region3int16_type_ok", true)
                    else
                        hard("region3int16_type_wrong", ok_r3 and typeof(r3) or tostring(r3))
                    end
                    local ok_mp = pcall(function()
                        local m = Instance.new("MeshPart")
                        assert(typeof(m.DoubleSided) == "boolean", "DoubleSided not boolean")
                        assert(typeof(m.RenderFidelity) == "EnumItem", "RenderFidelity not EnumItem")
                        m:Destroy()
                    end)
                    if ok_mp then pass("meshpart_properties_ok", true)
                    else hard("meshpart_properties_wrong", true) end
                    local ok_pp = pcall(function()
                        local p = Instance.new("Part", workspace)
                        local pr = Instance.new("ProximityPrompt", p)
                        pr.ActionText = "Use"
                        assert(pr.ActionText == "Use", "ActionText roundtrip failed")
                        p:Destroy()
                    end)
                    if ok_pp then pass("proximityprompt_actiontext_ok", true)
                    else hard("proximityprompt_actiontext_wrong", true) end
                    local ok_hl = pcall(function()
                        local h = Instance.new("Highlight")
                        h.FillColor = Color3.new(1,0,0)
                        assert(typeof(h.FillColor) == "Color3", "FillColor not Color3")
                        h:Destroy()
                    end)
                    if ok_hl then pass("highlight_fillcolor_ok", true)
                    else hard("highlight_fillcolor_wrong", true) end
                    local ok_wc = pcall(function()
                        local p1 = Instance.new("Part", workspace)
                        local p2 = Instance.new("Part", workspace)
                        local w = Instance.new("WeldConstraint", p1)
                        w.Part0 = p1; w.Part1 = p2
                        assert(w.Part0 == p1 and w.Part1 == p2, "WeldConstraint refs wrong")
                        p1:Destroy(); p2:Destroy()
                    end)
                    if ok_wc then pass("weldconstraint_parts_ok", true)
                    else hard("weldconstraint_parts_wrong", true) end
                    local ok_hd = pcall(function()
                        local d = Instance.new("HumanoidDescription")
                        assert(typeof(d.BodyTypeScale) == "number", "BodyTypeScale not number")
                        d:Destroy()
                    end)
                    if ok_hd then pass("humanoiddescription_bodyscale_ok", true)
                    else hard("humanoiddescription_bodyscale_wrong", true) end
                    local ok_ao = pcall(function()
                        local a = Instance.new("AlignOrientation")
                        assert(typeof(a) == "Instance")
                        a:Destroy()
                        local b = Instance.new("Actor")
                        assert(typeof(b) == "Instance")
                        b:Destroy()
                    end)
                    if ok_ao then pass("alignorientation_actor_ok", true)
                    else hard("alignorientation_actor_wrong", true) end
                    local ok_svc = pcall(function()
                        local a = game:GetService("AnimationClipProvider")
                        local m = game:GetService("MeshContentProvider")
                        assert(a ~= m, "providers are same ref")
                        assert(a:IsA("AnimationClipProvider"), "not AnimationClipProvider")
                    end)
                    if ok_svc then pass("service_identity_distinct", true)
                    else hard("service_identity_wrong", true) end
                    local ok_ms = pcall(function()
                        local a = game:GetService("AnimationClipProvider")
                        local stats = a:GetMemStats()
                        assert(type(stats) == "table", "GetMemStats not table")
                        local _, v = next(stats)
                        assert(v == nil or type(v) == "number",
                            "GetMemStats value not nil/number: " .. type(v))
                    end)
                    if ok_ms then pass("animclip_memstats_ok", true)
                    else hard("animclip_memstats_wrong", true) end
                    local ok_cam = pcall(function()
                        local cam = workspace.CurrentCamera
                        local ray = cam:ScreenPointToRay(100, 100)
                        assert(typeof(ray.Origin) == "Vector3", "ray.Origin not Vector3")
                    end)
                    if ok_cam then pass("screenpointtoray_ok", true)
                    else hard("screenpointtoray_wrong", true) end
                    local ok_cf2 = pcall(function()
                        local cf = CFrame.new(5,2,1)
                        local p = Vector3.new(1,0,0)
                        local rt = cf:PointToObjectSpace(cf:PointToWorldSpace(p))
                        assert((rt - p).Magnitude < 1e-4, "roundtrip magnitude: " .. (rt-p).Magnitude)
                    end)
                    if ok_cf2 then pass("cframe_pointspace_roundtrip_ok", true)
                    else hard("cframe_pointspace_roundtrip_wrong", true) end
                    local ok_gui = pcall(function()
                        local gs = game:GetService("GuiService")
                        assert(typeof(gs:GetGuiInset()) == "Vector2", "GetGuiInset not Vector2")
                        assert(typeof(gs:IsTenFootInterface()) == "boolean",
                            "IsTenFootInterface not boolean")
                    end)
                    if ok_gui then pass("guiservice_methods_ok", true)
                    else hard("guiservice_methods_wrong", true) end
                    local ok_vr = pcall(function()
                        local cf = game:GetService("VRService"):GetUserCFrame(Enum.UserCFrame.Head)
                        assert(typeof(cf) == "CFrame", "VRService CFrame type: " .. typeof(cf))
                    end)
                    if ok_vr then pass("vrservice_usercframe_ok", true)
                    else soft("vrservice_usercframe_unavailable", true) end
                    local ok_phys = pcall(function()
                        local ps = game:GetService("PhysicsService")
                        local ok_cg, id = pcall(function()
                            return ps:GetCollisionGroupId("Default")
                        end)
                        if not ok_cg then
                            -- Modern API: use CollisionGroups list instead
                            local ok_cg2, groups = pcall(function()
                                return ps:GetRegisteredCollisionGroups()
                            end)
                            if ok_cg2 and type(groups) == "table" then
                                local found = false
                                for _, g in ipairs(groups) do
                                    if g.name == "Default" then found = true; id = g.id break end
                                end
                                assert(found, "Default collision group not found")
                            end
                        end
                        assert(typeof(id) == "number", "collision group id not number: " .. typeof(id))
                    end)
                    if ok_phys then pass("physicservice_collisiongroup_ok", true)
                    else hard("physicservice_collisiongroup_wrong", true) end
                    local ok_ts2 = pcall(function()
                        local t = setmetatable({}, {__tostring = function() return "ok" end})
                        assert(tostring(t) == "ok", "tostring __tostring wrong: " .. tostring(t))
                    end)
                    if ok_ts2 then pass("tostring_metamethod_ok", true)
                    else hard("tostring_metamethod_wrong", true) end
                    if type(debug) == "table" and type(debug.info) == "function" then
                        local native_fns = {
                            {"pcall",pcall},{"type",type},{"rawget",rawget},
                            {"tostring",tostring},{"error",error},
                            {"setmetatable",setmetatable},{"ipairs",ipairs},
                            {"pairs",pairs},{"next",next},
                        }
                        for _, pair in ipairs(native_fns) do
                            local name, fn = pair[1], pair[2]
                            local ok_di2, src, line = pcall(debug.info, fn, "sl")
                            if ok_di2 then
                                if src ~= "[C]" or line ~= -1 then
                                    hard("native_sl_wrong:" .. name,
                                        {src=src, line=line})
                                else
                                    pass("native_sl_ok:" .. name, true)
                                end
                            end
                        end
                        if type(debug.traceback) == "function" then
                            local ok_dbt, src_dbt, ln_dbt = pcall(debug.info, debug.traceback, "sl")
                            if ok_dbt and (src_dbt ~= "[C]" or ln_dbt ~= -1) then
                                hard("debug_traceback_not_native",
                                    {src=src_dbt, line=ln_dbt})
                            else
                                pass("debug_traceback_native_ok", true)
                            end
                        end
                    end
                    local t1_cmp = os.clock()
                    for i = 1, 500 do local a,b="x","x"; local _=(a==b) end
                    local d1_cmp = os.clock() - t1_cmp
                    local t2_cmp = os.clock()
                    for i = 1, 500 do local a,b="x"..i,"x"..i; local _=(a==b) end
                    local d2_cmp = os.clock() - t2_cmp
                    if d1_cmp >= d2_cmp * 5 then
                        hard("literal_compare_suspiciously_slow",
                            {literal=d1_cmp, concat=d2_cmp})
                    else
                        pass("literal_compare_speed_ok", true)
                    end
                    local ok_cp2 = pcall(function()
                        local cp = game:GetService("CorePackages")
                        assert(tostring(cp.Parent) == "Ugc",
                            "CorePackages.Parent: " .. tostring(cp.Parent))
                    end)
                    if ok_cp2 then pass("corepackages_parent_ugc", true)
                    else hard("corepackages_parent_wrong", true) end
                    local ok_st = pcall(function()
                        local st = game:GetService("Stats")
                        assert(typeof(st.PerformanceStats) == "Instance",
                            "PerformanceStats: " .. typeof(st.PerformanceStats))
                    end)
                    if ok_st then pass("stats_performancestats_ok", true)
                    else hard("stats_performancestats_wrong", true) end
                do
                    local ok_m2 = pcall(function()
                        local df = game:GetService("SoundService").DistanceFactor
                        assert(df > 0, "not positive")
                        local rt = (df * math.pi) / math.pi
                        assert(math.abs(rt - df) <= 1e-5, "roundtrip broken: " .. rt)
                    end)
                    if ok_m2 then pass("soundservice_distancefactor_ok", true)
                    else hard("soundservice_distancefactor_wrong", true) end
                    local ok_m4 = pcall(function()
                        local cs = game:GetService("CollectionService")
                        local tag = "VH_" .. tostring(math.floor(math.log(8,2)*1000))
                        local part = Instance.new("Part", workspace)
                        cs:AddTag(part, tag)
                        local tagged = cs:GetTagged(tag)
                        assert(type(tagged)=="table" and #tagged==1
                            and tagged[1]==part, "AddTag roundtrip failed")
                        cs:RemoveTag(part, tag)
                        local after = cs:GetTagged(tag)
                        assert(#after==0, "RemoveTag failed: " .. #after)
                        part:Destroy()
                    end)
                    if ok_m4 then pass("collectionservice_tag_roundtrip_ok", true)
                    else hard("collectionservice_tag_roundtrip_wrong", true) end
                    local log8 = math.floor(math.log(8,2)*1000)
                    if log8 == 3000 then pass("math_log8_base2_correct", true)
                    else hard("math_log8_base2_wrong", log8) end
                    local enum_samples = {
                        {"EasingStyle","Bounce"},{"EasingDirection","InOut"},
                        {"Material","Plastic"},{"NormalId","Top"},
                        {"KeyCode","Space"},{"HumanoidStateType","Running"},
                        {"RaycastFilterType","Exclude"},{"BulkMoveMode","FireCFrameChanged"},
                        {"CameraType","Custom"},{"ChatStyle","Classic"},
                        {"CollisionFidelity","Default"},{"CoreGuiType","PlayerList"},
                        {"DeviceType","Desktop"},{"DialogTone","Friendly"},
                        {"ExplosionType","NoCraters"},{"Font","Arial"},
                        {"MembershipType","None"},{"SortOrder","Name"},
                        {"UserInputType","Keyboard"},{"AssetType","Model"},
                        {"BodyPart","Head"},{"BorderMode","Outline"},
                        {"ButtonStyle","Custom"},{"CameraMode","Classic"},
                        {"ConnectionState","Connected"},{"CurrencyType","Robux"},
                        {"AudioSubType","Music"},{"CompressionAlgorithm","Zstd"},
                        {"AutomaticSize","None"},{"Axis","X"},
                        {"ElasticBehavior","WhenScrollable"},{"BodyPartR15","Head"},
                    }
                    local enum_bad = 0
                    for _, pair in ipairs(enum_samples) do
                        local ok_e, e_err = pcall(function()
                            local fam = Enum[pair[1]]
                            assert(fam, "family missing")
                            local item = fam[pair[2]]
                            assert(item, "item missing")
                            assert(item.Value ~= nil, "Value nil")
                            local expected = "Enum." .. pair[1] .. "." .. pair[2]
                            assert(tostring(item) == expected,
                                "tostring: " .. tostring(item))
                        end)
                        if not ok_e then
                            enum_bad = enum_bad + 1
                            soft("enum_sample_wrong:" .. pair[1] .. "." .. pair[2],
                                tostring(e_err))
                        end
                    end
                    if enum_bad == 0 then
                        pass("enum_sampler_" .. #enum_samples .. "_valid", true)
                    end
                    local ok_m7 = pcall(function()
                        local all = Enum:GetEnums()
                        assert(type(all)=="table" and #all > 100,
                            "count: " .. tostring(all and #all or "nil"))
                    end)
                    if ok_m7 then pass("enum_getEnums_count_ok", true)
                    else hard("enum_getEnums_count_wrong", true) end
                    local ok_m8 = pcall(function()
                        assert(Enum.KeyCode.Space.EnumType == Enum.KeyCode,
                            "KeyCode.Space.EnumType mismatch")
                        assert(Enum.Material.Plastic.EnumType == Enum.Material,
                            "Material.Plastic.EnumType mismatch")
                    end)
                    if ok_m8 then pass("enum_enumtype_matches_parent", true)
                    else hard("enum_enumtype_wrong", true) end
                end
                end
            end
            local ok_adv, err_adv = pcall(check_advanced_environment)
            if not ok_adv then
                soft("check_advanced_environment_threw", tostring(err_adv))
            end
            local function _rob_fp()
                local env = _G
                if type(getfenv) == "function" then
                    local ok, r = pcall(getfenv, 1); if ok and type(r) == "table" then env = r end
                end
                local score = 0
                local mix = 0
                local game_obj = rawget(env, "game") or rawget(_G, "game")
                local instance = rawget(env, "Instance") or rawget(_G, "Instance")
                local v3i16 = rawget(env, "Vector3int16") or rawget(_G, "Vector3int16")
                local part = rawget(env, "Part") or rawget(_G, "Part")
                local cframe = rawget(env, "CFrame") or rawget(_G, "CFrame")
                local raycast_params = rawget(env, "RaycastParams") or rawget(_G, "RaycastParams")
                local function class_of(v)
                    local ok, r = safe_call(function() return v.ClassName end)
                    if ok then return r end
                    return nil
                end
                local function get_service_obj(obj, name)
                    local ok, r = safe_call(function() return obj:GetService(name) end)
                    if ok then return r end
                    return nil
                end
                local ok_game = game_obj ~= nil and type(game_obj) ~= "table" and class_of(game_obj) == "DataModel"
                if ok_game then
                    score = score + 1
                    mix = mix + 73
                else
                    mix = mix + 11
                end
                local ok_instance = false
                local folder = nil
                if instance ~= nil and type(instance.new) == "function" then
                    local ok, r = safe_call(instance.new, "Folder")
                    if ok then
                        folder = r
                        ok_instance = class_of(folder) == "Folder" and folder.Name == "Folder"
                    end
                end
                if ok_instance then
                    score = score + 1
                    mix = mix + 106
                else
                    mix = mix + 42
                end
                local players = game_obj and get_service_obj(game_obj, "Players") or nil
                local ok_players = players ~= nil and class_of(players) == "Players"
                if ok_players then
                    score = score + 1
                    mix = mix + 157
                else
                    mix = mix + 61
                end
                local ok_vector = false
                if v3i16 ~= nil and type(v3i16.new) == "function" then
                    local ok, r = safe_call(v3i16.new, 1, 2, 3)
                    if ok and r then
                        ok_vector = r.X == 1 and r.Y == 2 and r.Z == 3
                    end
                end
                if ok_vector then
                    score = score + 1
                    mix = mix + 104
                else
                    mix = mix + 29
                end
                local ok_geometry = part ~= nil or cframe ~= nil or raycast_params ~= nil
                if ok_geometry then
                    score = score + 1
                    mix = mix + 497
                else
                    mix = mix + 97
                end
                return score, mix
            end
            local function _dbg_fp()
                local score = 0
                local bad = 0
                local d = debug
                if type(d) ~= "table" then return 0, 8 end
                local function debug_info(fn, what)
                    if type(d.info) ~= "function" then return nil end
                    local ok, r = safe_call(d.info, fn, what)
                    if ok then return r end
                    return nil
                end
                if type(d.info) == "function" then
                    local s = debug_info(d.info, "s")
                    if s == "[C]" or s == nil then
                        score = score + 1
                    else
                        bad = bad + 1
                    end
                else
                    bad = bad + 1
                end
                if type(d.traceback) == "function" then
                    local s = debug_info(d.traceback, "s")
                    if s == "[C]" or s == nil then
                        score = score + 1
                    else
                        bad = bad + 1
                    end
                else
                    bad = bad + 1
                end
                if type(pcall) == "function" then
                    local s = debug_info(pcall, "s")
                    if s == "[C]" or s == nil then
                        score = score + 1
                    else
                        bad = bad + 1
                    end
                else
                    bad = bad + 1
                end
                if type(string) == "table" and type(string.match) == "function" then
                    local s = debug_info(string.match, "s")
                    if s == "[C]" or s == nil then
                        score = score + 1
                    else
                        bad = bad + 1
                    end
                else
                    bad = bad + 1
                end
                if type(d.traceback) == "function" then
                    local ok, tb = safe_call(d.traceback)
                    if ok and type(tb) == "string" then
                        local lines = 1
                        for _ in tb:gmatch("\n") do lines = lines + 1 end
                        if lines > 64 then bad = bad + 1 else score = score + 1 end
                    else
                        bad = bad + 1
                    end
                end
                local function probe() return 1 end
                local line = debug_info(probe, "l")
                if type(line) == "number" then
                    score = score + 1
                else
                    bad = bad + 1
                end
                return score, bad
            end
            local function _hook_fp()
                local env = _G
                if type(getfenv) == "function" then
                    local ok, r = pcall(getfenv, 1); if ok and type(r) == "table" then env = r end
                end
                local names = {
                    "hookfunction", "hookfunc", "restorefunction", "isfunctionhooked",
                    "newcclosure", "clonefunction", "getgc", "getregistry",
                    "getrawmetatable", "setreadonly", "WYNF_NO_VIRTUALIZE"
                }
                local score = 0
                for i, name in ipairs(names) do
                    local v = rawget(env, name) or rawget(_G, name)
                    if v ~= nil then
                        score = score + i * 17
                    end
                end
                return score
            end
            local function _env_fp()
                local env = _G
                if type(getfenv) == "function" then
                    local ok, r = pcall(getfenv, 1); if ok and type(r) == "table" then env = r end
                end
                local score = 0
                if type(getfenv) ~= "function" then score = score + 7 end
                if type(setfenv) ~= "function" then score = score + 11 end
                if type(rawget) ~= "function" then score = score + 13 end
                if type(setmetatable) ~= "function" then score = score + 19 end
                local mt = nil
                local ok, r = safe_call(getmetatable, env)
                if ok then mt = r end
                if type(mt) == "table" then
                    local metamethods = {
                        "__index", "__newindex", "__namecall", "__iter",
                        "__pairs", "__ipairs", "__len", "__metatable", "__tostring"
                    }
                    for i, mm in ipairs(metamethods) do
                        if rawget(mt, mm) ~= nil then
                            score = score + i * 23
                        end
                    end
                end
                return score
            end
            local function _keys()
                local roblox_score, roblox_mix = _rob_fp()
                local debug_score, debug_bad = _dbg_fp()
                local hook_score = _hook_fp()
                local env_score = _env_fp()
                local jm = 336113460
                if roblox_score < 4 then
                    jm = (jm + roblox_mix + 624781371) % 2147483647
                end
                if debug_bad > 0 then
                    jm = (jm + debug_bad * 658175227 + debug_score) % 2147483647
                end
                if hook_score > 0 then
                    jm = (jm + hook_score * 425412217) % 2147483647
                end
                if env_score > 0 then
                    jm = (jm + env_score * 1885244899) % 2147483647
                end
                local J9 = (688970746 + 1885244899 + jm) % 4294967296
                local K7_88 = 392018361
                if jm ~= 336113460 or debug_bad > 0 or hook_score > 0 or env_score > 0 then
                    K7_88 = (K7_88 + jm + hook_score + env_score + debug_bad) % 2147483647
                end
                return {
                    jm = jm,
                    J9 = J9,
                    K7_88 = K7_88,
                    valid = (jm == 336113460 and K7_88 == 392018361)
                }
            end
            local k = _keys()
            if not k.valid then
                hard("key_validation_failed", { jm = k.jm, J9 = k.J9, K7_88 = k.K7_88 })
            else
                pass("key_validation_passed", true)
            end
            local function _check(v, n)
                if not v then
                    hard(n, v)
                else
                    pass(n, true)
                end
            end
            local _err0 = error
            local _tos0 = tostring
            local _typ0 = type
            local _pc0 = pcall
            local _typof = typeof
            local function _fail(v)
                local s = _tos0(v)
                if _typ0(GUF_CRASH) == "function" then _pc0(GUF_CRASH, s) end
                hard("GUF_CRASH_fail", s)
            end
            local function _check_wrap(v, n)
                if not v then
                    _fail(n)
                else
                    pass(n, true)
                end
            end
            local function _probe_task_defer()
                task.defer(function()
                    local ok = _pc0(function() return coroutine.running() end)
                    _check(ok, "task.defer")
                end)
            end
            _probe_task_defer()
            local tcs = game:GetService("TextChatService")
            _check(tcs ~= nil, "TextChatService")
            local v3 = Vector3int16.new(32767, -32768, 1337)
            local v2 = Vector2int16.new(32767, -32768)
            _check(_typof(v3) == "Vector3int16", "Vector3int16")
            _check(_typof(v2) == "Vector2int16", "Vector2int16")
            _check(v3.X == 32767 and v3.Y == -32768 and v3.Z == 1337, "Vector3int16 fields")
            _check(v2.X == 32767 and v2.Y == -32768, "Vector2int16 fields")
            _check(_VERSION == "Luau", "_VERSION")
            _check(_typ0(elapsedTime) == "function", "elapsedTime")
            _check(_typ0(ElapsedTime) == "function", "ElapsedTime")
            -- ElapsedTime and elapsedTime are different refs in current Roblox — soft only
            _check(_typ0(math) == "table", "math")
            -- BrickColor.new(798641) error message varies by version — remove hard checks
            local pal_ok, pal_err = _pc0(function() return BrickColor.new(798641) end)
            _check(_typ0(FloatCurveKey) == "table", "FloatCurveKey")
            _check(_typ0(FloatCurveKey.new) == "function", "FloatCurveKey.new")
            _check(Enum ~= nil and Enum.KeyInterpolationMode ~= nil and Enum.KeyInterpolationMode.Linear ~= nil, "KeyInterpolationMode")
            local key_ok, key = _pc0(FloatCurveKey.new, 0.125, 1337.5, Enum.KeyInterpolationMode.Linear)
            _check(key_ok, "FloatCurveKey.new valid")
            _check(_typof(key) == "FloatCurveKey", "FloatCurveKey typeof")
            _check(key.Time == 0.125, "FloatCurveKey.Time")
            _check(key.Value == 1337.5, "FloatCurveKey.Value")
            _check(key.Interpolation == Enum.KeyInterpolationMode.Linear, "FloatCurveKey.Interpolation")
            local bad_int = _pc0(FloatCurveKey.new, 1, 2, "Linear")
            _check(not bad_int, "FloatCurveKey interpolation type")
            local bad_arity = _pc0(FloatCurveKey.new)
            _check(not bad_arity, "FloatCurveKey arity")
            _check(_typ0(Instance) == "table" and _typ0(Instance.new) == "function", "Instance.new")
            local curve = Instance.new("FloatCurve")
            _check(_typof(curve) == "Instance", "FloatCurve instance")
            local set_ok = _pc0(function() return curve:SetKeys({key}) end)
            _check(set_ok, "FloatCurve.SetKeys")
            local get_ok, key_at = _pc0(function() return curve:GetKeyAtIndex(1) end)
            _check(get_ok, "FloatCurve.GetKeyAtIndex")
            _check(_typof(key_at) == "FloatCurveKey", "GetKeyAtIndex typeof")
            _check(key_at.Time == key.Time, "GetKeyAtIndex Time")
            _check(key_at.Value == key.Value, "GetKeyAtIndex Value")
            _check(key_at.Interpolation == key.Interpolation, "GetKeyAtIndex Interpolation")
            local keys_ok, keys = _pc0(function() return curve:GetKeys() end)
            _check(keys_ok and _typ0(keys) == "table", "FloatCurve.GetKeys")
            _check(#keys == 1, "FloatCurve.GetKeys length")
            local val_ok, val = _pc0(function() return curve:GetValueAtTime(0.125) end)
            _check(val_ok, "FloatCurve.GetValueAtTime")
            _check(val == 1337.5, "FloatCurve value")
            curve:Destroy()
            local function _env_probe()
                local result = {}
                result.env           = getfenv()
                result.global        = _G
                result.set_meta      = setmetatable
                result.get_meta      = getmetatable
                result.protected_call= pcall
                result.throw         = error
                result.byte          = string.byte
                result.xor           = bit32 and bit32.bxor
                result.zero          = "\0"
                result.guf_crash     = rawget(_G, "GUF_CRASH")
                local tcs_ok, tcs = pcall(function() return game:GetService("TextChatService") end)
                result.text_chat_service = tcs_ok and tcs or nil
                local vx_ok, vx = pcall(function() return Vector3.new(17468, 1, 1).X end)
                result.vector_x = vx_ok and vx or nil
                local v2_ok, v2 = pcall(function() return Vector2int16.new(100, 200) end)
                result.vector2int16_ok = v2_ok and v2 ~= nil
                result.version_string  = _VERSION
                local ver_ok, ver      = false, nil
                if type(version) == "function" then ver_ok, ver = pcall(version) end
                result.version_result  = ver_ok and ver or nil
                local Ver_ok, Ver      = false, nil
                if type(Version) == "function" then Ver_ok, Ver = pcall(Version) end
                result.Version_result  = Ver_ok and Ver or nil
                result.elapsed_is_fn   = type(elapsedTime) == "function"
                result.Elapsed_is_fn   = type(ElapsedTime) == "function"
                result.elapsed_alias   = true
                local el_ok, el        = false, nil
                if type(elapsedTime) == "function" then el_ok, el = pcall(elapsedTime) end
                result.elapsed_result  = el_ok and type(el) == "number"
                result.palette         = true -- BrickColor.palette removed (unreliable)
                return result
            end
            task.defer(function() end)
            local probe = _env_probe()
            _check(type(probe.env)            == "table",    "probe_env")
            _check(type(probe.global)         == "table",    "probe_global")
            _check(type(probe.set_meta)       == "function", "probe_setmetatable")
            _check(type(probe.get_meta)       == "function", "probe_getmetatable")
            _check(type(probe.protected_call) == "function", "probe_pcall")
            _check(type(probe.throw)          == "function", "probe_error")
            _check(type(probe.byte)           == "function", "probe_string_byte")
            _check(type(probe.zero)           == "string",   "probe_zero_string")
            _check(probe.guf_crash == nil or type(probe.guf_crash) == "function", "probe_GUF_CRASH")
            _check(probe.text_chat_service ~= nil,           "probe_TextChatService")
            -- vector_x: vector.create API varies, soft only
            if probe.vector_x ~= 17468 then soft("probe_vector_x", probe.vector_x) else pass("probe_vector_x", true) end
            _check(probe.vector2int16_ok == true,            "probe_Vector2int16")
            _check(probe.version_string == "Luau",           "probe_VERSION")
            _check(type(probe.version_result) == "string",   "probe_version_fn")
            _check(type(probe.Version_result) == "string",   "probe_Version_fn")
            if probe.version_result and probe.Version_result then
                _check(probe.version_result == probe.Version_result, "probe_version_alias")
            else
                pass("probe_version_alias_skipped", true)
            end
            _check(type(probe.elapsed_result) == "boolean" and probe.elapsed_result == true, "probe_elapsedTime")
            _check(probe.elapsed_is_fn == true, "probe_elapsedTime_fn")
            _check(probe.Elapsed_is_fn == true, "probe_ElapsedTime_fn")
            -- string.find and BrickColor.palette vary by context — soft only
            do
                local n = 0
                local t0 = os.clock()
                local c = game:GetService("RunService").Heartbeat:Connect(function() n = n + 1 end)
                repeat task.wait() until n >= 3 or (os.clock() - t0) > 5
                c:Disconnect()
                if n < 3 then
                    hard("heartbeat_not_fired", n)
                else
                    pass("heartbeat_fired", n)
                end
            end
            do
                local ok, err = pcall(function()
                    Instance.new("Part"):InvalidMethod("a")
                end)
                if ok then
                    hard("invalid_method_did_not_error", true)
                else
                    pass("invalid_method_errored", err)
                end
            end
            do
                local ok, err = pcall(function()
                    game:GetChildren(function() while true do end end)
                end)
                if ok then
                    hard("getchildren_accepted_invalid_argument", true)
                else
                    pass("getchildren_with_function_errored", err)
                end
            end
            do
                local ok_gc, children = pcall(function() return game:GetChildren() end)
                if not ok_gc then
                    hard("game_getchildren_failed", tostring(children))
                elseif #children <= 4 then
                    hard("game_children_count_too_low", #children)
                else
                    pass("game_children_count_ok", #children)
                end
            end
            do
                local http = game:GetService("HttpService")
                local ok, result = pcall(function()
                    return http:JSONDecode('[68, "getgold.cc", true, 123, false, [321, null, "goldtm"], null, ["a"]]')
                end)
                if not ok then
                    hard("json_decode_failed", result)
                else
                    if result[6] and result[6][2] ~= nil then
                        hard("json_structure_mismatch", result[6][2])
                    else
                        pass("json_structure_valid", true)
                    end
                end
            end
            do
                local ok, svc = pcall(function() return game.HttpService end)
                if not ok or svc == nil then
                    hard("game_httpService_missing", svc)
                else
                    pass("game_httpService_exists", true)
                end
            end
            do
                if type(getfenv) == "function" then
                    local sentinel_key = "__at_probe_" .. tostring(math.random(1e9))
                    local sentinel_val = math.random(1e9)
                    _G[sentinel_key] = sentinel_val
                    local ok_gf, env = pcall(getfenv)
                    local read_val = ok_gf and env and rawget(env, sentinel_key)
                    _G[sentinel_key] = nil
                    if ok_gf and env ~= nil and read_val ~= sentinel_val then
                        hard("environment_G_getfenv_decoupled", true)
                    else
                        pass("environment_G_getfenv_coupled", true)
                    end
                else
                    pass("getfenv_unavailable", true)
                end
            end
            do
                local ok, err = pcall(function() game() end)
                if ok then
                    hard("game_call_did_not_error", true)
                else
                    if type(err) == "string" and string.find(err, "attempt to call a Instance value") then
                        pass("game_call_error_correct", err)
                    else
                        hard("game_call_wrong_error", err)
                    end
                end
            end
            do
                local randomMsg = "[" .. tostring(math.random()) .. "]"
                local logged = false
                local conn = game:GetService("LogService").MessageOut:Connect(function(msg, msgType)
                    if msg == randomMsg and msgType == Enum.MessageType.MessageOutput then
                        logged = true
                    end
                end)
                print(randomMsg)
                local start = os.clock()
                repeat task.wait() until logged or os.clock() - start > 1
                conn:Disconnect()
                if not logged then
                    hard("print_not_logged_by_LogService", randomMsg)
                else
                    pass("print_logged_by_LogService", true)
                end
            end
            report.hard_failure_count = #report.hard_failures
            report.soft_signal_count = #report.soft_signals
            report.passed_count = #report.passed
            report.blocked = report.hard_failure_count > 0 or report.soft_signal_count >= 8
            if diagnostic_mode then
                return report
            end
            if report.blocked then
                _err0("invalid binary", 0)
            end
            return true
        end
    ]=]
    local useDebugStr = self.UseDebug and "true" or "false"
    local diagStr = self.DiagnosticMode and "true" or "false"
    local code = string.format([[
        do
            local _outer_err0 = error
            local diagnostic_mode = %s
            local use_debug = %s
            %s
            local function is_hooked(fn)
                if type(fn) ~= "function" then return true end
                if type(debug) ~= "table" then return false end
                if type(debug.info) == "function" then
                    local ok, src = pcall(debug.info, fn, "s")
                    if not ok then return false end
                    return src ~= "[C]" and src ~= nil
                elseif type(debug.getinfo) == "function" then
                    local ok, info = pcall(debug.getinfo, fn)
                    if not ok or type(info) ~= "table" then return false end
                    return info.what ~= "C"
                end
                return false
            end
            if is_hooked(pcall) or is_hooked(error) then
                _outer_err0("Tamper: core functions hooked", 0)
            end
            local function secure_call()
                local ok = pcall(anti_tamper, diagnostic_mode, use_debug)
                if not ok then
                    _outer_err0("Tamper detected", 0)
                end
            end
            secure_call()
            if not is_loadstring then
                task.spawn(function()
                    while true do
                        task.wait(2 + math.random())
                        secure_call()
                    end
                end)
                local __anti_ref = anti_tamper
                task.spawn(function()
                    while true do
                        task.wait(1)
                        if anti_tamper ~= __anti_ref then
                            _outer_err0("Tamper: function replaced", 0)
                        end
                    end
                end)
            end
            local function _fake_return_empty(_) return "" end
            local function _fake_is_admin()      return false end
            local function _fake_decrypt_key(cb, _)
                cb(); return ({})[1]
            end
            local _fake_config_mt_inner = {}
            local _fake_config_mt = setmetatable({}, {
                __index    = function(_, k) _fake_config_mt_inner(); return k end,
                __newindex = function(_, _, _) _fake_config_mt_inner() end,
            })
            local _expected_honeypot = {
                fake_decrypt_key  = _fake_decrypt_key,
                fake_is_admin     = _fake_is_admin,
                fake_config_mt    = _fake_config_mt,
                fake_vm_master_key = 3735928559,
            }
            local _honey_env = getfenv and (function()
                local ok, e = pcall(getfenv, 1); return (ok and type(e) == "table") and e or _G
            end)() or _G
            _honey_env.fake_decrypt_key   = _fake_decrypt_key
            _honey_env.fake_is_admin      = _fake_is_admin
            _honey_env.fake_config_mt     = _fake_config_mt
            _honey_env.fake_vm_master_key = 3735928559
            local function _at_noop()
                local r = 0; if r == 0 then r = 99 end; return r
            end
            if not is_loadstring then
                task.spawn(function()
                    while true do
                        task.wait(5)
                        local env = _honey_env
                        if env.fake_decrypt_key   ~= _expected_honeypot.fake_decrypt_key   then secure_call() end
                        if env.fake_is_admin      ~= _expected_honeypot.fake_is_admin       then secure_call() end
                        if env.fake_config_mt     ~= _expected_honeypot.fake_config_mt      then secure_call() end
                        if env.fake_vm_master_key ~= _expected_honeypot.fake_vm_master_key  then secure_call() end
                        if env.fake_decrypt_key   == nil
                        or env.fake_is_admin      == nil
                        or env.fake_config_mt     == false then
                            _at_noop()
                        end
                        if env.fake_decrypt_key ~= _expected_honeypot.fake_decrypt_key
                        or env.fake_is_admin    ~= _expected_honeypot.fake_is_admin
                        or env.fake_config_mt   ~= _expected_honeypot.fake_config_mt
                        or env.fake_vm_master_key ~= _expected_honeypot.fake_vm_master_key then
                            secure_call()
                        end
                    end
                end)
            end
        end
    ]], diagStr, useDebugStr, antiTamperFunc)
    local parsed = Parser:new({ LuaVersion = Enums.LuaVersion.Lua51 }):parse(code);
    local doStat = parsed.body.statements[1];
    doStat.body.scope:setParent(ast.body.scope);
    table.insert(ast.body.statements, 1, doStat);
    return ast;
end
return AntiTamper;
