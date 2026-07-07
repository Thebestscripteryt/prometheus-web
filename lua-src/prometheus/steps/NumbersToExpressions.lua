-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- NumbersToExpressions.lua
--
-- This Script provides an Obfuscation Step, that converts Number Literals to expressions
--
-- Originally only produced Add/Sub decompositions (a+b, a-b). The two
-- multiplication-based decompositions below (a*b+c, a*b-c) are loosely
-- inspired by the multi-variant number obfuscator used in the Clyde-Luau-
-- Obfuscator project (MIT License, Copyright (c) 2025 Clyde:
-- https://github.com/sfr-development/Clyde-Luau-Obfuscator), reimplemented
-- from scratch against Prometheus's own AST/Step API. Having more than one
-- structural "shape" of expression makes the output harder to fingerprint,
-- since a static analyzer can no longer assume every obfuscated number
-- literal looks like a plain sum or difference.
unpack = unpack or table.unpack;

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local visitast = require("prometheus.visitast");
local util     = require("prometheus.util")

local AstKind = Ast.AstKind;

local NumbersToExpressions = Step:extend();
NumbersToExpressions.Description = "This Step Converts number Literals to Expressions";
NumbersToExpressions.Name = "Numbers To Expressions";

NumbersToExpressions.SettingsDescriptor = {
	Treshold = {
        type = "number",
        default = 1,
        min = 0,
        max = 1,
    },
    InternalTreshold = {
        type = "number",
        default = 0.2,
        min = 0,
        max = 0.8,
    }
}

function NumbersToExpressions:init(settings)
	self.ExpressionGenerators = {
        function(val, depth) -- Addition
            local val2 = math.random(-2^20, 2^20);
            local diff = val - val2;
            if tonumber(tostring(diff)) + tonumber(tostring(val2)) ~= val then
                return false;
            end
            return Ast.AddExpression(self:CreateNumberExpression(val2, depth), self:CreateNumberExpression(diff, depth), false);
        end, 
        function(val, depth) -- Subtraction
            local val2 = math.random(-2^20, 2^20);
            local diff = val + val2;
            if tonumber(tostring(diff)) - tonumber(tostring(val2)) ~= val then
                return false;
            end
            return Ast.SubExpression(self:CreateNumberExpression(diff, depth), self:CreateNumberExpression(val2, depth), false);
        end,
        function(val, depth) -- Multiplication decomposition: (a * b) + c
            -- Only safe for integers; non-integer values fall through to the
            -- other generators.
            if val ~= math.floor(val) then
                return false;
            end
            local a = math.random(2, 12);
            local b = math.floor(val / a);
            local c = val - a * b;
            if a * b + c ~= val then
                return false;
            end
            return Ast.AddExpression(
                Ast.MulExpression(self:CreateNumberExpression(a, depth), self:CreateNumberExpression(b, depth), false),
                self:CreateNumberExpression(c, depth),
                false
            );
        end,
        function(val, depth) -- Multiplication decomposition: (a * b) - c
            if val ~= math.floor(val) then
                return false;
            end
            local a = math.random(2, 12);
            local b = math.ceil(val / a) + math.random(0, 5);
            local c = a * b - val;
            if a * b - c ~= val then
                return false;
            end
            return Ast.SubExpression(
                Ast.MulExpression(self:CreateNumberExpression(a, depth), self:CreateNumberExpression(b, depth), false),
                self:CreateNumberExpression(c, depth),
                false
            );
        end
    }
end

function NumbersToExpressions:CreateNumberExpression(val, depth)
    if depth > 0 and math.random() >= self.InternalTreshold or depth > 15 then
        return Ast.NumberExpression(val)
    end

    local generators = util.shuffle({unpack(self.ExpressionGenerators)});
    for i, generator in ipairs(generators) do
        local node = generator(val, depth + 1);
        if node then
            return node;
        end
    end

    return Ast.NumberExpression(val)
end

function NumbersToExpressions:apply(ast)
	visitast(ast, nil, function(node, data)
        if node.kind == AstKind.NumberExpression then
            if math.random() <= self.Treshold then
                return self:CreateNumberExpression(node.value, 0);
            end
        end
    end)
end

return NumbersToExpressions;
