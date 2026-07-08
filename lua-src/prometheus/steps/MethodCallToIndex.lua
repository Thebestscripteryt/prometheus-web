-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- MethodCallToIndex.lua
--
-- This Step rewrites method-call syntax (`base:name(args)`) into plain
-- index + call syntax (`base["name"](base, args)`), evaluating `base`
-- exactly once via a fresh temporary so side effects are preserved.
--
-- Why this matters: `a.b` and `a["b"]` already parse to the exact same
-- IndexExpression(base, StringExpression("b")) node in this codebase, so
-- EncryptStrings/ConstantArray/SplitStrings already sweep up ordinary
-- member names for free. Method-call syntax is different: the parser
-- stores the method name as a raw Lua string field
-- (`passSelfFunctionName`) directly on the call node instead of as a
-- StringExpression child, so no later string-based step ever visits or
-- encrypts it. That means names like `:GetFullName()`, `:gsub()`,
-- `:Destroy()`, `:FindFirstChild()` etc. leak in **plaintext** in the
-- output even with every other string-hiding step enabled at maximum
-- settings. This step converts them into ordinary IndexExpression /
-- FunctionCallExpression nodes so they become normal StringExpression
-- children - i.e. so later steps like EncryptStrings actually catch them.
--
-- Run this step BEFORE EncryptStrings / ConstantArray / SplitStrings in
-- the pipeline so the newly-introduced string nodes get encrypted too.

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local visitast = require("prometheus.visitast");

local AstKind = Ast.AstKind;

local MethodCallToIndex = Step:extend();
MethodCallToIndex.Description = "This Step converts method-call syntax (a:b(...)) into index + call syntax (a[\"b\"](a, ...)), so method names stop leaking in plaintext and become subject to string encryption.";
MethodCallToIndex.Name = "Method Call To Index";

MethodCallToIndex.SettingsDescriptor = {}

function MethodCallToIndex:init(settings)

end

-- Statement form: `base:name(args);` used purely as a statement.
-- Rewritten as two statements so no closure is needed:
--   local tmp = base;
--   tmp["name"](tmp, args);
local function expandStatement(statement, scope)
	local id = scope:addVariable();
	local localDecl = Ast.LocalVariableDeclaration(scope, { id }, { statement.base });

	local args = { Ast.VariableExpression(scope, id) };
	for i, arg in ipairs(statement.args) do
		args[i + 1] = arg;
	end

	local newCall = Ast.FunctionCallStatement(
		Ast.IndexExpression(Ast.VariableExpression(scope, id), Ast.StringExpression(statement.passSelfFunctionName)),
		args
	);

	return localDecl, newCall;
end

-- Expression form: `base:name(args)` used as a value, e.g. inside another
-- call or an assignment. Must stay a single expression, so it's wrapped in
-- an immediately-invoked function that receives `base` as its only
-- argument, guaranteeing single evaluation regardless of side effects:
--   (function(tmp) return tmp["name"](tmp, args); end)(base)
local function expandExpression(expression, parentScope)
	local scope = Scope:new(parentScope);
	local id = scope:addVariable();
	local param = Ast.VariableExpression(scope, id);

	local args = { Ast.VariableExpression(scope, id) };
	for i, arg in ipairs(expression.args) do
		args[i + 1] = arg;
	end

	local call = Ast.FunctionCallExpression(
		Ast.IndexExpression(Ast.VariableExpression(scope, id), Ast.StringExpression(expression.passSelfFunctionName)),
		args
	);

	local body = Ast.Block({ Ast.ReturnStatement({ call }) }, scope);
	local literal = Ast.FunctionLiteralExpression({ param }, body);

	return Ast.FunctionCallExpression(literal, { expression.base });
end

function MethodCallToIndex:apply(ast)
	visitast(ast, nil, function(node, data)
		if node.kind == AstKind.PassSelfFunctionCallStatement then
			return expandStatement(node, data.scope);
		elseif node.kind == AstKind.PassSelfFunctionCallExpression then
			return expandExpression(node, data.scope);
		end
	end);
end

return MethodCallToIndex;
