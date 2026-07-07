-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- JunkCodeInsertion.lua
--
-- This Step inserts dead branches (`if <always-false predicate> then <junk> end`)
-- between existing statements throughout the program. The condition is a
-- fresh runtime arithmetic tautology built at each injection site (never a
-- fixed hardcoded check, so there is no single pattern to signature), and
-- it is always false - so the branch body never executes and program
-- behavior is completely unchanged.
--
-- This targets automated deobfuscators, decompilers, and structural/diff
-- based script-fingerprinting tools: every injected branch is an extra path
-- that has to be explored and ruled out before the "real" logic can be
-- recovered, and it pads/perturbs the statement shape of the script so it
-- no longer lines up with a known unobfuscated original.
--
-- Complements OpaquePredicates (which wraps *existing* conditions) by
-- adding entirely new, never-taken control-flow paths at arbitrary points
-- in the statement list - including inside functions that had no
-- conditions at all.

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local RandomStrings = require("prometheus.randomStrings");
local visitast = require("prometheus.visitast");
local util = require("prometheus.util");

local JunkCodeInsertion = Step:extend();
JunkCodeInsertion.Description = "This Step inserts dead (never-executed) branches containing junk code between statements, to confuse deobfuscators and pad structural fingerprints.";
JunkCodeInsertion.Name = "Junk Code Insertion";

JunkCodeInsertion.SettingsDescriptor = {
	Treshold = {
		type = "number",
		default = 0.2,
		min = 0,
		max = 1,
	},
	MaxJunkStatements = {
		type = "number",
		default = 3,
		min = 1,
		max = nil,
	},
}

function JunkCodeInsertion:init(settings)
	-- Each generator returns a fresh expression that always evaluates to
	-- `false`, built from a random operand chosen at the injection site.
	self.FalsePredicateGenerators = {
		function() -- (a * a) ~= a ^ 2 -- negation of a true identity
			local a = math.random(2, 5000);
			return Ast.NotEqualsExpression(
				Ast.MulExpression(Ast.NumberExpression(a), Ast.NumberExpression(a), false),
				Ast.PowExpression(Ast.NumberExpression(a), Ast.NumberExpression(2), false),
				false
			);
		end,
		function() -- (a + a) ~= (2 * a)
			local a = math.random(2, 5000);
			return Ast.NotEqualsExpression(
				Ast.AddExpression(Ast.NumberExpression(a), Ast.NumberExpression(a), false),
				Ast.MulExpression(Ast.NumberExpression(2), Ast.NumberExpression(a), false),
				false
			);
		end,
		function() -- (a - a) ~= 0
			local a = math.random(2, 5000);
			return Ast.NotEqualsExpression(
				Ast.SubExpression(Ast.NumberExpression(a), Ast.NumberExpression(a), false),
				Ast.NumberExpression(0),
				false
			);
		end,
		function() -- (a % 2 ~= 0) and (a % 2 ~= 1) -- impossible for any integer a
			local a = math.random(2, 5000);
			return Ast.AndExpression(
				Ast.NotEqualsExpression(Ast.ModExpression(Ast.NumberExpression(a), Ast.NumberExpression(2), false), Ast.NumberExpression(0), false),
				Ast.NotEqualsExpression(Ast.ModExpression(Ast.NumberExpression(a), Ast.NumberExpression(2), false), Ast.NumberExpression(1), false),
				false
			);
		end,
	};

	-- Builders for junk expressions used to fill dead-branch bodies. These
	-- never run, so they exist purely as noise for anyone reading or
	-- statically analyzing the decompiled/deobfuscated source.
	self.JunkExprGenerators = {
		function() return Ast.AddExpression(Ast.NumberExpression(math.random(1, 99999)), Ast.NumberExpression(math.random(1, 99999)), false); end,
		function() return Ast.MulExpression(Ast.NumberExpression(math.random(1, 999)), Ast.NumberExpression(math.random(1, 999)), false); end,
		function() return Ast.StrCatExpression(Ast.StringExpression(RandomStrings.randomString(math.random(3, 8))), Ast.StringExpression(RandomStrings.randomString(math.random(3, 8))), false); end,
		function() return Ast.NotExpression(Ast.BooleanExpression(math.random() > 0.5), false); end,
	};
end

function JunkCodeInsertion:CreateFalsePredicate()
	local generators = util.shuffle({ unpack(self.FalsePredicateGenerators) });
	return generators[1]();
end

-- Builds a self-contained dead block: every local it declares lives in its
-- own fresh scope, so the block never needs to reference (and is never
-- reachable from) anything outside the branch.
function JunkCodeInsertion:CreateJunkBlock(parentScope)
	local scope = Scope:new(parentScope);
	local statements = {};
	local count = math.random(1, self.MaxJunkStatements);
	local exprGenerators = self.JunkExprGenerators;
	for i = 1, count do
		local id = scope:addVariable();
		local generator = exprGenerators[math.random(1, #exprGenerators)];
		table.insert(statements, Ast.LocalVariableDeclaration(scope, { id }, { generator() }));
	end
	return Ast.Block(statements, scope);
end

function JunkCodeInsertion:CreateJunkIfStatement(parentScope)
	local condition = self:CreateFalsePredicate();
	local body = self:CreateJunkBlock(parentScope);
	return Ast.IfStatement(condition, body, {}, nil);
end

function JunkCodeInsertion:apply(ast)
	visitast(ast, nil, function(node, data)
		if not node.isStatement then
			return;
		end
		if math.random() > self.Treshold then
			return;
		end
		-- Insert a dead branch directly before this statement. Returning
		-- two statements here (junk, then the original) prepends the junk
		-- without altering or re-visiting the original node.
		local junkIf = self:CreateJunkIfStatement(data.scope);
		return junkIf, node;
	end);
end

return JunkCodeInsertion;
