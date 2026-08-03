-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- OpaquePredicates.lua
--
-- This Step injects always-true arithmetic tautologies ("opaque predicates")
-- into if/while/repeat conditions, e.g. turning `if cond then` into
-- `if (((a*a) == a^2)) and cond then`. The injected clause always evaluates
-- to true at runtime, but a static reader (human or tool) has to actually
-- reason about the arithmetic to know that - it can't tell at a glance
-- whether the condition genuinely depends on it.
--
-- Unlike a fixed small table of hardcoded predicates (which becomes a
-- recognizable fingerprint after seeing it a few times), every injected
-- predicate here uses a fresh random operand chosen at the injection site,
-- so no two injected checks look alike even within the same script.
--
-- Loosely inspired by the opaque-predicate concept used in the
-- Clyde-Luau-Obfuscator project (MIT License, Copyright (c) 2025 Clyde:
-- https://github.com/sfr-development/Clyde-Luau-Obfuscator), reimplemented
-- from scratch against Prometheus's own AST and Step API.

local unpack = unpack or table.unpack;

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local visitast = require("prometheus.visitast");
local util = require("prometheus.util");

local AstKind = Ast.AstKind;

local OpaquePredicates = Step:extend();
OpaquePredicates.Description = "This Step injects always-true arithmetic tautologies into if/while/repeat conditions";
OpaquePredicates.Name = "Opaque Predicates";

OpaquePredicates.SettingsDescriptor = {
    Treshold = {
        type = "number",
        default = 1,
        min = 0,
        max = 1,
    },
}

function OpaquePredicates:init(settings)
    -- Each generator returns an expression that always evaluates to `true`,
    -- built from a fresh random operand. Every returned node is a NEW node
    -- (never shared), since the same predicate may be needed at multiple
    -- injection sites within one traversal.
    self.PredicateGenerators = {
        function() -- (a * a) == a ^ 2
            local a = math.random(2, 5000);
            return Ast.EqualsExpression(
                Ast.MulExpression(Ast.NumberExpression(a), Ast.NumberExpression(a), false),
                Ast.PowExpression(Ast.NumberExpression(a), Ast.NumberExpression(2), false),
                false
            );
        end,
        function() -- (a + a) == (2 * a)
            local a = math.random(2, 5000);
            return Ast.EqualsExpression(
                Ast.AddExpression(Ast.NumberExpression(a), Ast.NumberExpression(a), false),
                Ast.MulExpression(Ast.NumberExpression(2), Ast.NumberExpression(a), false),
                false
            );
        end,
        function() -- ((a + 1) * (a + 1)) == ((a * a) + (2 * a) + 1) -- expansion of (a+1)^2
            local a = math.random(2, 5000);
            local aPlus1 = Ast.AddExpression(Ast.NumberExpression(a), Ast.NumberExpression(1), false);
            local left = Ast.MulExpression(aPlus1, Ast.AddExpression(Ast.NumberExpression(a), Ast.NumberExpression(1), false), false);
            local right = Ast.AddExpression(
                Ast.AddExpression(
                    Ast.MulExpression(Ast.NumberExpression(a), Ast.NumberExpression(a), false),
                    Ast.MulExpression(Ast.NumberExpression(2), Ast.NumberExpression(a), false),
                    false
                ),
                Ast.NumberExpression(1),
                false
            );
            return Ast.EqualsExpression(left, right, false);
        end,
        function() -- (a - a) == 0
            local a = math.random(2, 5000);
            return Ast.EqualsExpression(
                Ast.SubExpression(Ast.NumberExpression(a), Ast.NumberExpression(a), false),
                Ast.NumberExpression(0),
                false
            );
        end,
        function() -- (a % 2 == 0) or (a % 2 == 1)  -- always true for any positive integer a
            local a = math.random(2, 5000);
            return Ast.OrExpression(
                Ast.EqualsExpression(Ast.ModExpression(Ast.NumberExpression(a), Ast.NumberExpression(2), false), Ast.NumberExpression(0), false),
                Ast.EqualsExpression(Ast.ModExpression(Ast.NumberExpression(a), Ast.NumberExpression(2), false), Ast.NumberExpression(1), false),
                false
            );
        end,
    };
end

function OpaquePredicates:CreatePredicate()
    local generators = util.shuffle({unpack(self.PredicateGenerators)});
    return generators[1]();
end

-- Wraps an existing condition expression with a fresh opaque predicate,
-- combined via `and`, so the condition's real behavior is unchanged.
function OpaquePredicates:WrapCondition(condition)
    if math.random() > self.Treshold then
        return condition;
    end
    return Ast.AndExpression(self:CreatePredicate(), condition, false);
end

function OpaquePredicates:apply(ast)
    visitast(ast, nil, function(node, data)
        if node.kind == AstKind.IfStatement then
            node.condition = self:WrapCondition(node.condition);
            for i, eif in ipairs(node.elseifs) do
                eif.condition = self:WrapCondition(eif.condition);
            end
        elseif node.kind == AstKind.WhileStatement then
            node.condition = self:WrapCondition(node.condition);
        elseif node.kind == AstKind.RepeatStatement then
            -- A `repeat ... until cond` stops when cond is true, so wrapping it
            -- the same way as if/while (AND with an always-true predicate) is
            -- safe here too: `(true) and cond` is exactly equivalent to `cond`.
            node.condition = self:WrapCondition(node.condition);
        end
    end);
end

return OpaquePredicates;
