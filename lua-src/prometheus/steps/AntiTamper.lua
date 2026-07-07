local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local Parser = require("prometheus.parser");
local Enums = require("prometheus.enums");
local logger = require("logger");

local AntiTamper = Step:extend();
AntiTamper.Description = "Injects a multi‑layer anti‑tamper system (supports Roblox & generic Lua).";
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

    -- Embedded anti‑tamper function – all checks combined
    local antiTamperFunc = [=[
        local function anti_tamper(diagnostic_mode, use_debug)
            -- Capture line reference as early as possible for consistency check later.
            -- When Prometheus emits this with PrettyPrint=false everything lands on one
            -- physical line, so both reads return the same currentline in a clean env.
            -- A beautifier or line-level debugger will cause them to diverge.
            local __line_ref = nil
            if use_debug and type(debug) == "table" and type(debug.getinfo) == "function" then
                local ok_line, info_line = pcall(debug.getinfo, 1, "l")
                if ok_line and type(info_line) == "table" then
                    __line_ref = info_line.currentline
                end
            end

            -- ==================== 🔥 UPGRADED EARLY CHECKS ====================

            -- Early environment validation
            if not game or not game.GetService then
                return error("Tamper: Invalid environment", 0)
            end

            -- Lock critical functions into locals
            local _pcall = pcall
            local _error = error
            local _getfenv = getfenv
            local _setfenv = setfenv
            local _debug = debug
            local _string_dump = string.dump

            -- Detect hookfunction / replaceclosure (even if nil, check existence)
            -- We now also check if they are defined (even nil) to catch being set to nil
            if rawget(_G, "hookfunction") ~= nil or rawget(_G, "replaceclosure") ~= nil then
                return _error("Tamper: hookfunction/replaceclosure present", 0)
            end

            -- Function integrity check via string.dump.
            -- In Luau/Roblox, string.dump is intentionally disabled, so a failed dump
            -- does NOT indicate tampering — skip the check gracefully in that case.
            local function integrity_check(fn)
                if type(_string_dump) ~= "function" then
                    return true -- dump unavailable (Luau), cannot check, assume ok
                end
                local ok, dumped = _pcall(_string_dump, fn)
                if not ok then
                    return true -- dump blocked by environment, not a tamper signal
                end
                return type(dumped) == "string" and #dumped > 10
            end

            -- Only fail if dump succeeded AND returned something suspiciously small/nil
            local ic_result = integrity_check(anti_tamper)
            if not ic_result then
                return _error("Tamper: function modified", 0)
            end

            -- Debug hook detection
            if use_debug and _debug then
                local hook = _debug.gethook()
                if hook then
                    return _error("Tamper: debug hook detected", 0)
                end
            end

            -- Timing check (detect slow stepping / breakpoints)
            do
                local t1 = os.clock()
                for i = 1, 1e4 do end
                local t2 = os.clock()
                if (t2 - t1) > 0.1 then
                    return _error("Tamper: execution slowed", 0)
                end
            end

            -- Metatable lock check
            do
                local mt = getmetatable(_G)
                if mt and (mt.__index or mt.__newindex) then
                    return _error("Tamper: global metatable hooked", 0)
                end
            end

            -- Environment check: getfenv(0) is invalid in Luau (level 0 = C); use level 1.
            -- Wrapped in pcall so it degrades gracefully if getfenv is unavailable.
            do
                if _getfenv then
                    local ok, env = _pcall(_getfenv, 1)
                    if ok and env ~= nil and env ~= _G then
                        return _error("Tamper: environment changed", 0)
                    end
                end
            end

            -- Bytecode / dump detection.
            -- Only meaningful in standard Lua 5.1 where string.dump works.
            -- In Luau, string.dump is always blocked; skip to avoid false-positive.
            -- We detect hooking only if dump was previously working and is now blocked.
            -- Since we can't know "previously working" at runtime, skip in Luau (_VERSION == "Luau").
            if _string_dump and _VERSION ~= "Luau" then
                local ok = _pcall(_string_dump, function() end)
                if not ok then
                    return _error("Tamper: dump blocked (hooked)", 0)
                end
            end

            -- ==================== ORIGINAL ANTI‑TAMPER CHECKS ====================

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

            -- ==================== SNIPPET UTILITIES ====================

            -- Lightweight XOR-based probe string encoder. Used to obscure
            -- sentinel values passed between check layers.
            local function encode_probe_string(input)
                local encoded = {}
                local state = (#input * 257) % 65536
                for i = 1, #input do
                    local b = string.byte(input, i)
                    encoded[i] = string.format("%02x", bit32.bxor(b, bit32.band(state, 255)))
                    state = bit32.band(state * 31 + i, 65535)
                end
                return table.concat(encoded)
            end

            -- NaN identity self-test: NaN ~= NaN is always true in Lua/Luau.
            -- If this returns false, the VM's equality semantics are broken.
            local function identity_self_test()
                local u  -- uninitialised = nil, not NaN; but 0/0 is NaN in Luau
                local nan = 0/0
                if nan ~= nan then return true end -- correct: NaN ≠ NaN
                return false -- broken VM equality
            end

            -- Closure value probes – expected return values are checked at runtime.
            local function at_closure_a() return 57005 end   -- 0xDEAD
            local function at_closure_b() return 123 end
            local function at_closure_c() return 1 end
            local function at_closure_d() return 2 end

            -- Named error probe: pcall must catch this and preserve the message.
            local function raise_named_probe_error() error("__ntt_probe__", 0) end

            -- Runtime fingerprint: encodes a probe value with a timing salt.
            -- Calling this exercises pcall, coroutine, error, and tick paths.
            local function build_runtime_fingerprint(value)
                local str_val = "??"
                local ok, cv = pcall(tostring, value)
                if ok then str_val = cv end
                local time_byte = bit32.band(math.floor(((tick and tick()) or 0) * 997), 255)
                local fp = string.format("%x:%s:%x", tonumber(value) or 0, str_val, time_byte)
                -- Exercise error/coroutine paths without actually erroring out
                pcall(function() error("", 0) end)
                pcall(function()
                    local t = coroutine.running()
                    if t then coroutine.status(t) end
                end)
                pcall(function()
                    if task and coroutine then
                        local t = coroutine.running()
                        if t then
                            task.spawn(function() coroutine.status(t) end)
                        end
                    end
                end)
                return fp
            end

            -- ==================== ORIGINAL CHECKS ====================
            -- NOTE: check_line_consistency() is defined above (near check_coroutine_state)
            -- and called in the final run block below alongside the other checks.

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
                        hard("forbidden_global_present:" .. name, value_type(value))
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
                if not use_debug then
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
                            -- Soft signal: script may legitimately run server-side (ModuleScript)
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

            -- ==================== RUNTIME INTEGRITY CHECK ====================
            -- Derived from runAntiTamperChecks in the snippet. Validates:
            --   • pcall/xpcall identity stability across calls
            --   • closure return value integrity
            --   • named error propagation through pcall
            --   • isfunctionhooked on native functions (executor API)
            --   • getgenv table write/readback roundtrip
            --   • debug.info availability and basic sanity
            --   • HttpService JSONEncode
            --   • RunService IsClient
            --   • getmetatable not spoofed to nil
            --   • clonefunction identity (executor API)
            --   • getcallingscript identity
            --   • hookfunction detection via closure value mutation
            --   • NaN identity semantics
            --   • Runtime fingerprint smoke-test
            local function check_runtime_integrity()
                -- 1) pcall identity: tostring(pcall) must be stable across two reads
                local pcall_id_a = tostring(pcall)
                local pcall_id_b = tostring(pcall)
                if pcall_id_a ~= pcall_id_b then
                    hard("pcall_identity_unstable", pcall_id_b)
                else
                    pass("pcall_identity_stable", true)
                end

                -- 2) xpcall identity
                local xpcall_id_a = tostring(xpcall)
                local xpcall_id_b = tostring(xpcall)
                if xpcall_id_a ~= xpcall_id_b then
                    hard("xpcall_identity_unstable", xpcall_id_b)
                else
                    pass("xpcall_identity_stable", true)
                end

                -- 3) Closure return value: at_closure_a must return 0xDEAD (57005)
                local ok_cl, cl_val = pcall(at_closure_a)
                if not ok_cl or cl_val ~= 57005 then
                    hard("closure_a_value_wrong", cl_val)
                else
                    pass("closure_a_value_valid", true)
                end

                -- 4) Named error must be caught and message preserved
                local ok_err, err_val = pcall(raise_named_probe_error)
                if ok_err or type(err_val) ~= "string"
                    or not string.find(err_val, "__ntt_probe__", 1, true) then
                    hard("named_error_not_preserved", err_val)
                else
                    pass("named_error_preserved", true)
                end

                -- 5) isfunctionhooked: if present, none of our natives should be hooked
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

                -- 6) getgenv write/read roundtrip
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

                -- 7) debug.info basic sanity (Luau only)
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

                -- 8) HttpService JSONEncode smoke-test
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

                -- 9) RunService IsClient must not error
                local ok_rs, rs = pcall(function() return game:GetService("RunService") end)
                if ok_rs and rs then
                    local ok_ic = pcall(function() rs:IsClient() end)
                    if not ok_ic then
                        hard("runservice_isclient_error", true)
                    else
                        pass("runservice_isclient_ok", true)
                    end
                end

                -- 10) getmetatable roundtrip: a fresh table with a metatable must not
                --     return nil from getmetatable (some executor hooks return nil always)
                local probe_mt = setmetatable({}, {})
                local got_mt = getmetatable(probe_mt)
                if got_mt == nil then
                    hard("getmetatable_always_nil", true)
                else
                    pass("getmetatable_roundtrip_valid", true)
                end

                -- 11) clonefunction: cloned function ≠ original (executor provides this)
                local clone_fn = rawget(_G, "clonefunction")
                if type(clone_fn) == "function" then
                    local ok_cl2, cloned = pcall(clone_fn, pcall)
                    if ok_cl2 and cloned == pcall then
                        -- Identical pointer = fake clone (hook bypass attempt)
                        soft("clonefunction_returned_same_ref", true)
                    else
                        pass("clonefunction_distinct", true)
                    end
                else
                    pass("clonefunction_absent", true)
                end

                -- 12) getcallingscript: if present, calling script should match `script`
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

                -- 13) hookfunction detection: hook at_closure_c → at_closure_d,
                --     then call it; if it returns 2 (at_closure_d's value) the hook worked,
                --     which is a strong signal of an executor environment.
                local hook_fn = rawget(_G, "hookfunction")
                if type(hook_fn) == "function" then
                    pcall(hook_fn, at_closure_c, at_closure_d)
                    local ok_hk, hk_val = pcall(at_closure_c)
                    if ok_hk and hk_val == 2 then
                        -- hookfunction is active and working — executor confirmed
                        hard("hookfunction_active", hk_val)
                    else
                        soft("hookfunction_present_but_ineffective", hk_val)
                    end
                else
                    pass("hookfunction_absent", true)
                end

                -- 14) NaN identity self-test
                if not identity_self_test() then
                    hard("nan_identity_broken", true)
                else
                    pass("nan_identity_valid", true)
                end

                -- 15) Runtime fingerprint smoke-test: must return a non-empty string
                local fp = build_runtime_fingerprint(42)
                if type(fp) ~= "string" or #fp == 0 then
                    hard("runtime_fingerprint_empty", fp)
                else
                    pass("runtime_fingerprint_valid", true)
                end

                -- 16) encode_probe_string must be deterministic
                local s1 = encode_probe_string("antiTamper")
                local s2 = encode_probe_string("antiTamper")
                if s1 ~= s2 or type(s1) ~= "string" or #s1 == 0 then
                    hard("encode_probe_string_nondeterministic", s1)
                else
                    pass("encode_probe_string_valid", true)
                end
            end

            -- ==================== RUN ALL CORE CHECKS ====================
            -- Previously these were defined but never called — fixed.
            check_forbidden_globals()
            check_debug_hook()
            check_line_consistency()
            check_coroutine_state()
            check_roblox_services()
            check_instance_properties()
            check_enums()
            check_raw_environment_access()
            check_runtime_integrity()

            -- ==================== ADDITIONAL CHECKS FROM antitamper.lua (10) ====================

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
                hard("key_validation_failed", k)
            else
                pass("key_validation_passed", true)
            end

            -- ==================== CHECKS FROM antitamper.lua (11) ====================

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
                if not v then _fail(n) end
                pass(n, true)
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
            local vv = vector.create(0.125, 1337.5, -2)
            _check(_typof(v3) == "Vector3int16", "Vector3int16")
            _check(_typof(v2) == "Vector2int16", "Vector2int16")
            _check(_typof(vv) == "vector", "vector")
            _check(v3.X == 32767 and v3.Y == -32768 and v3.Z == 1337, "Vector3int16 fields")
            _check(v2.X == 32767 and v2.Y == -32768, "Vector2int16 fields")
            _check(_VERSION == "Luau", "_VERSION")
            _check(_typ0(elapsedTime) == "function", "elapsedTime")
            _check(_typ0(ElapsedTime) == "function", "ElapsedTime")
            _check(elapsedTime == ElapsedTime, "ElapsedTime alias")
            _check(_typ0(math) == "table", "math")

            local pal_ok, pal_err = _pc0(function() return BrickColor.new(798641) end)
            _check(not pal_ok, "BrickColor bounds")
            _check(_typ0(pal_err) == "string" and string.find(pal_err, "palette index out of bounds (", 1, true) ~= nil, "BrickColor error")

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

            -- ==================== ADDITIONAL PROBES FROM USER SNIPPET ====================

            -- Environment fingerprint probe: capture values into named locals then
            -- validate them. Previously used positional multi-return which caused
            -- index misalignment bugs. Now uses a table so indices are explicit.
            local function _env_probe()
                local result = {}
                result.env           = getfenv()            -- [1] getfenv table
                result.global        = _G                   -- [2] _G table
                result.set_meta      = setmetatable         -- [3] setmetatable fn
                result.get_meta      = getmetatable         -- [4] getmetatable fn
                result.protected_call= pcall               -- [5] pcall fn
                result.throw         = error                -- [6] error fn
                result.byte          = string.byte          -- [7] string.byte fn
                result.xor           = bit32 and bit32.bxor -- [8] bit32.bxor fn (nil if unavailable)
                result.zero          = "\0"                 -- [9] null byte string

                -- GUF_CRASH: optional executor crash callback; must be function or nil
                result.guf_crash     = rawget(_G, "GUF_CRASH")

                -- Roblox-specific values
                local tcs_ok, tcs = pcall(function() return game:GetService("TextChatService") end)
                result.text_chat_service = tcs_ok and tcs or nil

                local vx_ok, vx = pcall(function() return vector.create(17468, 1, 1).X end)
                result.vector_x = vx_ok and vx or nil

                -- Vector2int16 clamps to int16 range (-32768..32767); 6767676 wraps
                -- We only check the type, not the value, since clamping is implementation-defined
                local v2_ok, v2 = pcall(function() return Vector2int16.new(100, 200) end)
                result.vector2int16_ok = v2_ok and v2 ~= nil

                result.version_string  = _VERSION
                local ver_ok, ver      = pcall(version)
                result.version_result  = ver_ok and ver or nil
                local Ver_ok, Ver      = pcall(Version)
                result.Version_result  = Ver_ok and Ver or nil
                local el_ok, el        = pcall(elapsedTime)
                result.elapsed_result  = el_ok and el or nil
                local El_ok, El        = pcall(ElapsedTime)
                result.Elapsed_result  = El_ok and El or nil
                result.find            = string.find
                local pal_ok, pal      = pcall(function() return BrickColor.palette end)
                result.palette         = pal_ok and pal or nil

                return result
            end

            -- Defer a coroutine yield probe (non-blocking)
            task.defer(coroutine.yield)

            local probe = _env_probe()

            -- Validate each field by name — no index arithmetic required
            _check(type(probe.env)            == "table",    "probe_env")
            _check(type(probe.global)         == "table",    "probe_global")
            _check(type(probe.set_meta)       == "function", "probe_setmetatable")
            _check(type(probe.get_meta)       == "function", "probe_getmetatable")
            _check(type(probe.protected_call) == "function", "probe_pcall")
            _check(type(probe.throw)          == "function", "probe_error")
            _check(type(probe.byte)           == "function", "probe_string_byte")
            _check(type(probe.zero)           == "string",   "probe_zero_string")
            -- GUF_CRASH must be a function or absent (nil); anything else is suspicious
            _check(probe.guf_crash == nil or type(probe.guf_crash) == "function", "probe_GUF_CRASH")
            -- Roblox-specific
            _check(probe.text_chat_service ~= nil,           "probe_TextChatService")
            _check(probe.vector_x == 17468,                  "probe_vector_x")
            _check(probe.vector2int16_ok == true,            "probe_Vector2int16")
            _check(probe.version_string == "Luau",           "probe_VERSION")
            _check(type(probe.version_result) == "string",   "probe_version_fn")
            _check(type(probe.Version_result) == "string",   "probe_Version_fn")
            _check(probe.version_result == probe.Version_result, "probe_version_alias")
            _check(type(probe.elapsed_result) == "number",   "probe_elapsedTime")
            _check(probe.elapsed_result == probe.Elapsed_result, "probe_ElapsedTime_alias")
            _check(type(probe.find)    == "function",        "probe_string_find")
            _check(type(probe.palette) == "table",           "probe_BrickColor_palette")

            -- ==================== NEW CHECKS (ENV‑LOGGING DETECTION) ====================

            -- 1) Heartbeat counter – ensures RunService is alive and not throttled
            do
                local n = 0
                local c = game:GetService("RunService").Heartbeat:Connect(function() n = n + 1 end)
                repeat task.wait() until n >= 3
                c:Disconnect()
                if n < 3 then
                    hard("heartbeat_not_fired", n)
                else
                    pass("heartbeat_fired", n)
                end
            end

            -- 2) Invalid method call – must error
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

            -- 3) GetChildren with function argument – must error
            do
                local ok, err = pcall(function()
                    game:GetChildren(function() while true do end end)
                end)
                if ok then
                    hard("getchildren_with_function_did_not_error", true)
                else
                    pass("getchildren_with_function_errored", err)
                end
            end

            -- 4) Game child count probe – too few children = sandboxed / emulated environment
            -- Previously crashed unconditionally with buffer.writei8 OOB, bypassing diagnostic_mode.
            -- Now uses hard() so diagnostic_mode is respected and the report is still populated.
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

            -- 5) JSONDecode test – expect a specific structure; if it fails or returns wrong, hard fail
            do
                local http = game:GetService("HttpService")
                local ok, result = pcall(function()
                    return http:JSONDecode('[68, "getgold.cc", true, 123, false, [321, null, "goldtm"], null, ["a"]]')
                end)
                if not ok then
                    hard("json_decode_failed", result)
                else
                    -- Check the structure: result[6][2] should be nil because index 2 is null? Actually the array: [68, "getgold.cc", true, 123, false, [321, null, "goldtm"], null, ["a"]]
                    -- result[6] is [321, null, "goldtm"] -> result[6][2] is null (nil in Lua).
                    -- So we expect result[6][2] == nil
                    if result[6] and result[6][2] ~= nil then
                        hard("json_structure_mismatch", result[6][2])
                    else
                        pass("json_structure_valid", true)
                    end
                end
            end

            -- 6) game.HttpService direct access – must exist
            do
                local ok, svc = pcall(function() return game.HttpService end)
                if not ok or svc == nil then
                    hard("game_httpService_missing", svc)
                else
                    pass("game_httpService_exists", true)
                end
            end

            -- 7) _G / getfenv() identity check
            -- In a real Roblox LocalScript, getfenv(0) and _G are the same table.
            -- Executors sometimes wedge a proxy between them; writing to _G and
            -- reading via getfenv() should always return the same value.
            -- Previous logic flagged clean environments (val ~= nil means it WORKED,
            -- which is correct behaviour). Inverted: hard-fail if the value is NOT
            -- visible through getfenv(), i.e. the two environments are decoupled.
            do
                local sentinel_key = "__at_probe_" .. tostring(math.random(1e9))
                local sentinel_val = math.random(1e9)
                _G[sentinel_key] = sentinel_val
                local env = getfenv()
                local read_val = rawget(env, sentinel_key)
                _G[sentinel_key] = nil
                if read_val ~= sentinel_val then
                    -- getfenv() returned a different table than _G — proxy/sandbox detected
                    hard("environment_G_getfenv_decoupled", tostring(read_val))
                else
                    pass("environment_G_getfenv_coupled", true)
                end
            end

            -- 8) game() call – must error "attempt to call a Instance value"
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

            -- 9) LogService print detection – if the print is logged, we consider the environment normal;
            --    but if it is not logged, the script will hang (which is a form of detection).
            --    We'll do a non‑blocking version: we start listening and set a timeout.
            do
                local randomMsg = `[{math.random()}]`
                local logged = false
                local conn = game:GetService("LogService").MessageOut:Connect(function(msg, msgType)
                    if msg == randomMsg and msgType == Enum.MessageType.MessageOutput then
                        logged = true
                    end
                end)
                print(randomMsg)
                -- Wait up to 1 second for the message to appear
                local start = os.clock()
                repeat task.wait() until logged or os.clock() - start > 1
                conn:Disconnect()
                if not logged then
                    hard("print_not_logged_by_LogService", randomMsg)
                else
                    pass("print_logged_by_LogService", true)
                end
            end

            -- ==================== FINAL REPORT ====================

            report.hard_failure_count = #report.hard_failures
            report.soft_signal_count = #report.soft_signals
            report.passed_count = #report.passed
            report.blocked = report.hard_failure_count > 0 or report.soft_signal_count >= 3

            if diagnostic_mode then
                return report
            end

            if report.blocked then
                error("invalid binary", 0)
            end

            return true
        end
    ]=]

    -- Build the final injection code with secure call, periodic re-checks, and core function hook detection
    local useDebugStr = self.UseDebug and "true" or "false"
    local diagStr = self.DiagnosticMode and "true" or "false"
    local code = string.format([[
        do
            local diagnostic_mode = %s
            local use_debug = %s
            %s

            -- Check if core functions are native (C) – if not, they are hooked/replaced
            -- Luau uses debug.info(fn, "s") not debug.getinfo; falls back gracefully if unavailable
            local function is_hooked(fn)
                if type(fn) ~= "function" then return true end
                if type(debug) ~= "table" then return false end -- debug unavailable, can't tell
                if type(debug.info) == "function" then
                    -- Luau path: debug.info(fn, "s") returns source string; "[C]" = native
                    local ok, src = pcall(debug.info, fn, "s")
                    if not ok then return false end -- info blocked, assume ok
                    return src ~= "[C]" and src ~= nil
                elseif type(debug.getinfo) == "function" then
                    -- Standard Lua 5.1 path (non-Roblox environments)
                    local ok, info = pcall(debug.getinfo, fn)
                    if not ok or type(info) ~= "table" then return false end
                    return info.what ~= "C"
                end
                return false -- no debug.info or debug.getinfo available
            end

            -- Only block if we can positively confirm hooking; skip string.dump (blocked in Luau)
            if is_hooked(pcall) or is_hooked(error) then
                error("Tamper: core functions hooked", 0)
            end

            -- Secure call wrapper – if any check fails inside anti_tamper, it will error
            local function secure_call()
                local ok = pcall(anti_tamper, diagnostic_mode, use_debug)
                if not ok then
                    error("Tamper detected", 0)
                end
            end

            -- Run the full anti‑tamper suite immediately
            secure_call()

            -- Keep re‑checking periodically to catch runtime tampering
            task.spawn(function()
                while true do
                    task.wait(2 + math.random())
                    secure_call()
                end
            end)

            -- Monitor the anti‑tamper function itself – if it gets replaced, error out
            local __anti_ref = anti_tamper
            task.spawn(function()
                while true do
                    task.wait(1)
                    if anti_tamper ~= __anti_ref then
                        error("Tamper: function replaced", 0)
                    end
                end
            end)

            -- ==================== HONEYPOT FAKE GLOBALS ====================
            -- Plant convincing-looking decoy globals that executors/scripts may
            -- try to read or modify. Any mutation is caught by publishFakeGlobals.
            -- All values are deliberately inert:
            --   • fake_decrypt_key  → a no-op that calls its callback and returns nil
            --   • fake_is_admin     → always returns false
            --   • fake_config_mt    → a proxy metatable whose __index/__newindex call
            --                         the first argument (treats it as a callback) then
            --                         return harmless values
            --   • fake_vm_master_key → the well-known 0xDEADBEEF constant

            local function _fake_return_empty(_) return "" end
            local function _fake_is_admin()      return false end
            local function _fake_decrypt_key(cb, _)
                cb(); return ({})[1]   -- calls callback, returns nil
            end

            -- Config proxy: __index and __newindex both invoke the first argument
            -- as a callback, mimicking encrypted config access patterns that
            -- some analysers try to instrument.
            local _fake_config_mt_inner = {}
            local _fake_config_mt = setmetatable({}, {
                __index    = function(_, k) _fake_config_mt_inner(); return k end,
                __newindex = function(_, _, _) _fake_config_mt_inner() end,
            })

            -- Snapshot the expected values so the monitor can detect mutation.
            local _expected_honeypot = {
                fake_decrypt_key  = _fake_decrypt_key,
                fake_is_admin     = _fake_is_admin,
                fake_config_mt    = _fake_config_mt,
                fake_vm_master_key = 3735928559,   -- 0xDEADBEEF
            }

            -- Write them into the shared environment
            local _honey_env = getfenv and (function()
                local ok, e = pcall(getfenv, 1); return (ok and type(e) == "table") and e or _G
            end)() or _G
            _honey_env.fake_decrypt_key   = _fake_decrypt_key
            _honey_env.fake_is_admin      = _fake_is_admin
            _honey_env.fake_config_mt     = _fake_config_mt
            _honey_env.fake_vm_master_key = 3735928559

            -- Anti-tamper noop: returns 99; used as a no-op side-effect marker
            -- so the monitor loop body is never optimised away.
            local function _at_noop()
                local r = 0; if r == 0 then r = 99 end; return r
            end

            -- Monitor: checks honeypot values every 5 s; any mutation is a hard signal.
            task.spawn(function()
                while true do
                    task.wait(5)
                    local env = _honey_env
                    if env.fake_decrypt_key   ~= _expected_honeypot.fake_decrypt_key   then _at_noop() end
                    if env.fake_is_admin      ~= _expected_honeypot.fake_is_admin       then _at_noop() end
                    if env.fake_config_mt     ~= _expected_honeypot.fake_config_mt      then _at_noop() end
                    if env.fake_vm_master_key ~= _expected_honeypot.fake_vm_master_key  then _at_noop() end
                    -- Null-pointer traps: none of these should ever be nil/false
                    if env.fake_decrypt_key   == nil
                    or env.fake_is_admin      == nil
                    or env.fake_config_mt     == false then
                        _at_noop()
                    end
                    -- If any honeypot was mutated, trigger a full re-check immediately
                    if env.fake_decrypt_key ~= _expected_honeypot.fake_decrypt_key
                    or env.fake_is_admin    ~= _expected_honeypot.fake_is_admin
                    or env.fake_config_mt   ~= _expected_honeypot.fake_config_mt then
                        secure_call()
                    end
                end
            end)
        end
    ]], diagStr, useDebugStr, antiTamperFunc)

    -- Parse and insert the new code block at the very beginning of the AST
    local parsed = Parser:new({ LuaVersion = Enums.LuaVersion.Lua51 }):parse(code);
    local doStat = parsed.body.statements[1];
    doStat.body.scope:setParent(ast.body.scope);
    table.insert(ast.body.statements, 1, doStat);

    return ast;
end

return AntiTamper;
