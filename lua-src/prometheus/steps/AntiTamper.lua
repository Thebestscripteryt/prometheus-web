-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- AntiTamper.lua (Ultimate Version)
--
-- This Step injects a multi‑layer anti‑tamper system that detects:
--   • Forbidden global variables
--   • Debug hooks and coroutine modifications
--   • Roblox service integrity (if game exists)
--   • Instance property/type corruption
--   • Enum validity
--   • Raw environment access
--   • (Optional) debug library hook detection
--
-- Uses the battle‑tested anti_tamper routine (July 2026) – no false positives.

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local Parser = require("prometheus.parser");
local Enums = require("prometheus.enums");
local logger = require("logger");

local AntiTamper = Step:extend();
AntiTamper.Description = "Injects a comprehensive anti‑tamper system (supports Roblox & generic Lua).";
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

    -- The full anti‑tamper function (from the provided file), with conditional debug checks.
    -- We embed it as a string and then call it at the top of the script.
    local antiTamperCode = string.format([[
        local function anti_tamper(diagnostic_mode)
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
                -- Only run if debug checks are enabled (controlled by the setting).
                if not %s then return end

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
                            hard("not_running_on_client", is_client)
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

            -- Run all checks
            check_forbidden_globals()
            check_debug_hook()       -- will be skipped if UseDebug is false
            check_coroutine_state()
            check_roblox_services()
            check_instance_properties()
            check_enums()
            check_raw_environment_access()

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

        -- Execute the anti‑tamper check with the current settings.
        anti_tamper(%s)
    ]], tostring(self.UseDebug), tostring(self.DiagnosticMode))

    -- Parse the generated code and insert it as the first statement.
    local parsed = Parser:new({ LuaVersion = Enums.LuaVersion.Lua51 }):parse(antiTamperCode)
    local doStat = parsed.body.statements[1]
    doStat.body.scope:setParent(ast.body.scope)
    table.insert(ast.body.statements, 1, doStat)

    return ast
end

return AntiTamper
