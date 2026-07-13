-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- ConditionInverter.lua
--
-- Randomly rewrites `if cond then A else B end` as `if not(cond) then B else
-- A end`. Both forms are always exactly equivalent for any condition, since
-- this only relies on Lua's truthiness rules (every value is either
-- truthy or falsy) - unlike rewriting comparison operators (e.g. turning
-- `==` into combinations of `<`/`<=`), which requires knowing operand types
-- ahead of time (`<` errors on non-orderable values like tables or nil,
-- while `==` does not), this transform is safe for absolutely any
-- condition expression.
--
-- The point isn't to hide any single condition - `not(cond)` is trivially
-- reducible by a reader. It's that a script's conditions no longer have a
-- consistent polarity: the same kind of check might appear as its natural
-- form in one place and its inverted form (with swapped branches) in
-- another, defeating simple pattern-based signature matching across many
-- obfuscated samples.
--
-- Loosely inspired by the condition-polarity-flipping concept in
-- IronBrew2's TestFlip (MIT License, Copyright (c) 2019 DefCon42:
-- https://github.com/DigiDaz/IronBrew2), reimplemented from scratch here
-- at the AST level against Prometheus's own AST and Step API - IronBrew2's
-- version operates on compiled Lua bytecode instructions directly, which
-- is a different representation entirely.

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local visitast = require("prometheus.visitast");

local AstKind = Ast.AstKind;

local ConditionInverter = Step:extend();
ConditionInverter.Description = "This Step randomly inverts if/else conditions (swapping branches to compensate), varying the surface structure of the script's real conditions";
ConditionInverter.Name = "Condition Inverter";

ConditionInverter.SettingsDescriptor = {
    Treshold = {
        type = "number",
        default = 0.5,
        min = 0,
        max = 1,
    },
}

function ConditionInverter:init(settings)
end

function ConditionInverter:apply(ast)
    local treshold = self.Treshold;

    visitast(ast, nil, function(node, data)
        -- Only if-statements with a plain else (no elseifs) are eligible -
        -- keeping this narrowly scoped avoids having to reason about
        -- De Morgan-style rewrites across chains of elseif conditions,
        -- where a mistake would be much easier to get subtly wrong.
        if node.kind == AstKind.IfStatement and node.elsebody and #node.elseifs == 0 then
            if math.random() < treshold then
                node.condition = Ast.NotExpression(node.condition, false);
                node.body, node.elsebody = node.elsebody, node.body;
            end
        end
    end);
end

return ConditionInverter;
