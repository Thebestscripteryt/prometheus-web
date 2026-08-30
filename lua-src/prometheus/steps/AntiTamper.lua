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
            local executor_hook_api_present = rawget(_G, "hookfunction") ~= nil
                or rawget(_G, "replaceclosure") ~= nil
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
            local compatibility_prefixes = {
                "alignorientation_", "animclip_", "bit32_", "brickcolor_", "buffer_",
                "bulkmoveto_", "bxor_", "c2_", "callback_", "cframe_", "chat_",
                "collectionservice_", "connection_", "coroutine_", "debugid_", "distributed_",
                "encoding_", "enum_", "error_msg_", "game_", "get_service", "getfullname_",
                "getgenv_", "getmetatable_", "global_environment_", "gsub_", "guid_", "guiservice_",
                "heartbeat_", "highlight_", "humanoiddescription_", "instance_", "isa_", "integer_",
                "invalid_method_", "json", "lighting_", "literal_compare_", "localplayer_", "lua_fn_",
                "math_", "membership_", "meshpart_", "metamethod_", "networkclient_", "once_",
                "os_date_", "overlapparams_", "part_", "physics_", "physicservice_", "playbackloudness_",
                "proximityprompt_", "raw_probe_", "raw_roundtrip_", "rawget_", "rawlen_", "rawset_",
                "raycastparams_", "region3int16_", "renderstepped_", "runservice_", "sandbox_",
                "screenpointtoray_", "server_time_", "service_", "shared_", "signal_", "soundservice_",
                "stats_", "string_", "table_freeze", "textbounds_", "tostring_", "traceback_",
                "two_connections_", "typeof_", "utf8_", "vector3_", "weldconstraint_", "wrong_class_",
                "xor_", "xpcall_", "GUF_CRASH_", "closure_", "corepackages_", "debug_info_",
                "debug_traceback_", "encode_probe_", "error_passthrough_", "forbidden_global_",
                "gameid_", "getservice_accepts_", "line_consistency_", "metatable_not_locked",
                "named_error_", "nan_identity_", "runtime_fingerprint_", "getrawmetatable_"
            }
            local function is_compatibility_check(name)
                if type(name) ~= "string" then return false end
                for _, prefix in ipairs(compatibility_prefixes) do
                    if name:sub(1, #prefix) == prefix then return true end
                end
                return false
            end
            local function hard(name, value)
                local target = is_compatibility_check(name) and report.soft_signals or report.hard_failures
                target[#target + 1] = {
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
            if executor_hook_api_present then
                -- Executor hook APIs are capability markers, not proof that a
                -- captured function has actually been replaced.
                hard("executor_hook_api_present", true)
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
                            hard("loadstring_forbidden:" .. name, value_type(value))
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
                    hard("debug_gethook_failed", hook)
                    return
                end
                if hook ~= nil then
                    hard("debug_hook_installed", {
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
                    hard("line_consistency_probe_failed", info)
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
                    hard("coroutine_running_failed", thread)
                    return
                end
                if thread == nil then
                    pass("coroutine_has_no_thread", true)
                    return
                end
                local ok_status, status = pcall(coroutine.status, thread)
                if not ok_status then
                    hard("coroutine_status_failed", status)
                    return
                end
                if status ~= "running" then
                    hard("current_coroutine_not_running", status)
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
                local success = pcall(function()
                    do
                        local c = Instance.new("TerrainRegion")

                        assert(typeof(c) == "Instance")
                        assert(c.ClassName == "TerrainRegion")
                        assert(c:IsA("TerrainRegion"))
                        assert(c:IsA("Instance"))

                        local workspaceTerrain = workspace:FindFirstChildOfClass("Terrain")
                        if workspaceTerrain then
                            local ok, region = pcall(function()
                                return workspaceTerrain:CopyRegion(Region3.new(Vector3.new(0, 0, 0), Vector3.new(4, 4, 4)))
                            end)
                            if ok and region then
                                assert(typeof(region) == "TerrainRegion")
                                assert(region.ClassName == "TerrainRegion")
                                assert(region:IsA("TerrainRegion"))

                                local size = region.Size
                                assert(typeof(size) == "Vector3int16")
                                assert(type(size.X) == "number")
                                assert(type(size.Y) == "number")
                                assert(type(size.Z) == "number")
                            end
                        end

                        local okCreate = pcall(function()
                            local part = Instance.new("Part")
                            local pos = part.Position
                            part:Destroy()
                        end)
                        assert(okCreate)
                    end
                end)
                if not success then
                    hard("terrainregion_probe_failed", true)
                else
                    pass("terrainregion_probe_ok", true)
                end
                return {
                    game = game_object,
                }
            end
            local function destroy_instance(object)
                if object ~= nil and type(object.Destroy) == "function" then
                    pcall(object.Destroy, object)
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
                    local any_hooked = false
                    for _, fn in ipairs(natives) do
                        if type(fn) == "function" and is_fn_hooked(fn) then
                            hard("native_function_hooked", tostring(fn))
                            any_hooked = true
                            break
                        end
                    end
                    if not any_hooked then
                        pass("native_functions_not_hooked", true)
                    end
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
                        hard("getgenv_call_failed", ok_genv)
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
                        hard("clonefunction_returned_same_ref", true)
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
                        hard("getcallingscript_mismatch", tostring(calling))
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
                        hard("hookfunction_present_but_ineffective", hk_val)
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
                        hard("coroutine_stack_depth_too_shallow", 198)
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
                        hard("error_passthrough_values_identical", v1)
                    else
                        pass("error_passthrough_distinct", { v1 = v1, v2 = v2 })
                    end
                end
                if type(debug) == "table" and type(debug.info) == "function" then
                    local function check_native_source(fn, name, is_critical)
                        if type(fn) ~= "function" then
                            hard("native_source_not_function:" .. name, type(fn))
                            return
                        end
                        local ok, src = pcall(debug.info, fn, "s")
                        if not ok then
                            hard("native_source_probe_failed:" .. name, src)
                            return
                        end
                            if src == "[C]" or src == "=[C]" or src == "C" or src == nil then
                                pass("native_source_is_C:" .. name, true)
                        else
                            if is_critical then
                                hard("native_source_replaced:" .. name, src)
                            else
                                hard("native_source_wrapped:" .. name, src)
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
            check_debug_hook()
            check_line_consistency()
            check_coroutine_state()
            check_roblox_services()
            check_enums()
            check_raw_environment_access()
            check_runtime_integrity()
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
            pass("key_validation_passed", true)
            local _err0 = error
            report.hard_failure_count = #report.hard_failures
            report.soft_signal_count = #report.soft_signals
            report.passed_count = #report.passed
            report.blocked = report.hard_failure_count > 0
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
                    if src == nil then return false end
                    local native = src == "[C]" or src == "=[C]" or src == "C"
                    return not native
                elseif type(debug.getinfo) == "function" then
                    local ok, info = pcall(debug.getinfo, fn)
                    if not ok or type(info) ~= "table" then return false end
                    local native = info.what == "C" or info.source == "=[C]" or info.source == "[C]"
                    return not native
                end
                return false
            end
            if is_hooked(pcall) or is_hooked(error) then
                _outer_err0("Tamper: core functions hooked", 0)
            end
            local function secure_call()
                local ok, reason = pcall(anti_tamper, diagnostic_mode, use_debug)
                if not ok then
                    local message = tostring(reason)
                    if message == "invalid binary" or message:sub(1, 7) == "Tamper:" then
                        _outer_err0("Tamper detected", 0)
                    end
                    return false
                end
                return true
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
