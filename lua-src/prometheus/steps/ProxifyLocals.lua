

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local visitast = require("prometheus.visitast");

local AstKind = Ast.AstKind;
local unpack = unpack or table.unpack;

local ProifyLocals = Step:extend();
ProifyLocals.Description = "This Step wraps all locals into Proxy Objects";
ProifyLocals.Name = "Proxify Locals";

ProifyLocals.SettingsDescriptor = {
	LiteralType = {
		name = "LiteralType",
		description = "The type of the randomly generated literals",
		type = "enum",
		values = {
			"dictionary",
			"number",
			"string",
            "any",
		},
		default = "string",
	},
}

local function shallowcopy(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in pairs(orig) do
            copy[orig_key] = orig_value
        end
    else
        copy = orig
    end
    return copy
end

local function callNameGenerator(generatorFunction, ...)
	if(type(generatorFunction) == "table") then
		generatorFunction = generatorFunction.generateName;
	end
	return generatorFunction(...);
end

local MetatableExpressions = {
    {
        constructor = Ast.AddExpression,
        key = "__add";
    },
    {
        constructor = Ast.SubExpression,
        key = "__sub";
    },
    {
        constructor = Ast.IndexExpression,
        key = "__index";
    },
    {
        constructor = Ast.MulExpression,
        key = "__mul";
    },
    {
        constructor = Ast.DivExpression,
        key = "__div";
    },
    {
        constructor = Ast.PowExpression,
        key = "__pow";
    },
    {
        constructor = Ast.StrCatExpression,
        key = "__concat";
    }
}

function ProifyLocals:init(settings)

end

local function generateLocalMetatableInfo(pipeline)
    local usedOps = {};
    local info = {};
    for i, v in ipairs({"setValue","getValue", "index"}) do
        local rop;
        repeat
            rop = MetatableExpressions[math.random(#MetatableExpressions)];
        until not usedOps[rop];
        usedOps[rop] = true;
        info[v] = rop;
    end

    info.valueName = callNameGenerator(pipeline.namegenerator, math.random(1, 4096));

    return info;
end

function ProifyLocals:CreateAssignmentExpression(info, expr, parentScope)
    local metatableVals = {};

    local containerScope = Scope:new(parentScope);
    local containerArg = containerScope:addVariable();

    local setValueFunctionScope = Scope:new(containerScope);
    local setValueSelf = setValueFunctionScope:addVariable();
    local setValueArg = setValueFunctionScope:addVariable();
    local setvalueFunctionLiteral = Ast.FunctionLiteralExpression(
        {
            Ast.VariableExpression(setValueFunctionScope, setValueSelf),
            Ast.VariableExpression(setValueFunctionScope, setValueArg),
        },
        Ast.Block({
            Ast.AssignmentStatement({
                Ast.AssignmentIndexing(Ast.VariableExpression(setValueFunctionScope, setValueSelf), Ast.StringExpression(info.valueName));
            }, {
                Ast.VariableExpression(setValueFunctionScope, setValueArg)
            })
        }, setValueFunctionScope)
    );
    local setValueId = containerScope:addVariable();
    table.insert(metatableVals, Ast.KeyedTableEntry(Ast.StringExpression(info.setValue.key), Ast.VariableExpression(containerScope, setValueId)));

    local getValueFunctionScope = Scope:new(containerScope);
    local getValueSelf = getValueFunctionScope:addVariable();
    local getValueArg = getValueFunctionScope:addVariable();
    local getValueIdxExpr;
    if(info.getValue.key == "__index" or info.setValue.key == "__index") then
        getValueIdxExpr = Ast.FunctionCallExpression(Ast.VariableExpression(getValueFunctionScope:resolveGlobal("rawget")), {
            Ast.VariableExpression(getValueFunctionScope, getValueSelf),
            Ast.StringExpression(info.valueName),
        });
    else
        getValueIdxExpr = Ast.IndexExpression(Ast.VariableExpression(getValueFunctionScope, getValueSelf), Ast.StringExpression(info.valueName));
    end
    local getvalueFunctionLiteral = Ast.FunctionLiteralExpression(
        {
            Ast.VariableExpression(getValueFunctionScope, getValueSelf),
            Ast.VariableExpression(getValueFunctionScope, getValueArg),
        },
        Ast.Block({
            Ast.ReturnStatement({
                getValueIdxExpr;
            });
        }, getValueFunctionScope)
    );
    local getValueId = containerScope:addVariable();
    table.insert(metatableVals, Ast.KeyedTableEntry(Ast.StringExpression(info.getValue.key), Ast.VariableExpression(containerScope, getValueId)));

    containerScope:addReferenceToHigherScope(self.setMetatableVarScope, self.setMetatableVarId);
    local proxyResult = Ast.FunctionCallExpression(
        Ast.VariableExpression(self.setMetatableVarScope, self.setMetatableVarId),
        {
            Ast.TableConstructorExpression({
                Ast.KeyedTableEntry(Ast.StringExpression(info.valueName), Ast.VariableExpression(containerScope, containerArg))
            }),
            Ast.TableConstructorExpression(metatableVals)
        }
    );

    return Ast.FunctionCallExpression(
        Ast.FunctionLiteralExpression({
            Ast.VariableExpression(containerScope, containerArg)
        }, Ast.Block({
            Ast.LocalVariableDeclaration(containerScope, {setValueId}, {setvalueFunctionLiteral});
            Ast.LocalVariableDeclaration(containerScope, {getValueId}, {getvalueFunctionLiteral});
            Ast.ReturnStatement({proxyResult});
        }, containerScope)),
        {expr}
    );
end

function ProifyLocals:apply(ast, pipeline)
    local localMetatableInfos = {};
    local function getLocalMetatableInfo(scope, id)

        if(scope.isGlobal) then return nil end;

        localMetatableInfos[scope] = localMetatableInfos[scope] or {};
        if localMetatableInfos[scope][id] then

            if localMetatableInfos[scope][id].locked then
                return nil
            end
            return localMetatableInfos[scope][id];
        end
        local localMetatableInfo = generateLocalMetatableInfo(pipeline);
        localMetatableInfos[scope][id] = localMetatableInfo;
        return localMetatableInfo;
    end

    local function disableMetatableInfo(scope, id)

        if(scope.isGlobal) then return nil end;

        localMetatableInfos[scope] = localMetatableInfos[scope] or {};
        localMetatableInfos[scope][id] = {locked = true}
    end

    self.setMetatableVarScope = ast.body.scope;
    self.setMetatableVarId    = ast.body.scope:addVariable();

    self.emptyFunctionScope   = ast.body.scope;
    self.emptyFunctionId      = ast.body.scope:addVariable();
    self.emptyFunctionUsed    = false;

    local invokerScope = Scope:new(ast.body.scope);
    local invokerFnArg = invokerScope:addVariable();
    local invokerArgA  = invokerScope:addVariable();
    local invokerArgB  = invokerScope:addVariable();
    local invokerArgC  = invokerScope:addVariable();

    table.insert(ast.body.statements, 1, Ast.LocalVariableDeclaration(self.emptyFunctionScope, {self.emptyFunctionId}, {
        Ast.FunctionLiteralExpression({
            Ast.VariableExpression(invokerScope, invokerFnArg),
            Ast.VariableExpression(invokerScope, invokerArgA),
            Ast.VariableExpression(invokerScope, invokerArgB),
            Ast.VariableExpression(invokerScope, invokerArgC),
        }, Ast.Block({
            Ast.ReturnStatement({
                Ast.FunctionCallExpression(Ast.VariableExpression(invokerScope, invokerFnArg), {
                    Ast.VariableExpression(invokerScope, invokerArgA),
                    Ast.VariableExpression(invokerScope, invokerArgB),
                    Ast.VariableExpression(invokerScope, invokerArgC),
                });
            });
        }, invokerScope));
    }));
	
    self.readHelperScope = ast.body.scope;
    self.readHelperId    = ast.body.scope:addVariable();

    local readHelperScope = Scope:new(ast.body.scope);
    local readHelperValueArg = readHelperScope:addVariable();
    local readHelperKeyArg   = readHelperScope:addVariable();
    local readHelperTypeScope, readHelperTypeId     = readHelperScope:resolveGlobal("type");
    local readHelperRawgetScope, readHelperRawgetId = readHelperScope:resolveGlobal("rawget");
    readHelperScope:addReferenceToHigherScope(readHelperTypeScope, readHelperTypeId);
    readHelperScope:addReferenceToHigherScope(readHelperRawgetScope, readHelperRawgetId);

    local readHelperValue = Ast.VariableExpression(readHelperScope, readHelperValueArg);
    local readHelperKey   = Ast.VariableExpression(readHelperScope, readHelperKeyArg);
    local readHelperCondition = Ast.EqualsExpression(
        Ast.FunctionCallExpression(Ast.VariableExpression(readHelperTypeScope, readHelperTypeId), { readHelperValue }),
        Ast.StringExpression("table"),
        false
    );
    local readHelperThen = Ast.Block({
        Ast.ReturnStatement({Ast.FunctionCallExpression(
            Ast.VariableExpression(readHelperRawgetScope, readHelperRawgetId),
            { readHelperValue, readHelperKey }
        )})
    }, readHelperScope);
    local readHelperElse = Ast.Block({
        Ast.ReturnStatement({readHelperValue})
    }, readHelperScope);
    local readHelperBranch = Ast.IfStatement(readHelperCondition, readHelperThen, {}, readHelperElse);

    table.insert(ast.body.statements, 1, Ast.LocalVariableDeclaration(self.readHelperScope, {self.readHelperId}, {
        Ast.FunctionLiteralExpression({readHelperValue, readHelperKey}, Ast.Block({readHelperBranch}, readHelperScope))
    }));

    visitast(ast, function(node, data)
        if(node.kind == AstKind.FunctionDeclaration and #node.indices > 0) then
            disableMetatableInfo(node.scope, node.id);
        end

        if(node.kind == AstKind.LocalFunctionDeclaration) then
            disableMetatableInfo(node.scope, node.id);
        end

        if(node.kind == AstKind.LocalVariableDeclaration and #node.ids > #node.expressions) then
            for _, id in ipairs(node.ids) do
                disableMetatableInfo(node.scope, id);
            end
        end
    end, nil);

    visitast(ast, function(node, data)

        if(node.kind == AstKind.ForStatement) then
            disableMetatableInfo(node.scope, node.id)
        end
        if(node.kind == AstKind.ForInStatement) then
            for i, id in ipairs(node.ids) do
                disableMetatableInfo(node.scope, id);
            end
        end

        if(node.kind == AstKind.FunctionDeclaration or node.kind == AstKind.LocalFunctionDeclaration or node.kind == AstKind.FunctionLiteralExpression) then
            for i, expr in ipairs(node.args) do
                if expr.kind == AstKind.VariableExpression then
                    disableMetatableInfo(expr.scope, expr.id);
                end
            end
        end

        if(node.kind == AstKind.AssignmentStatement) then
            if(#node.lhs > 1) then
                local doScope = Scope:new(node.lhs[1].scope);
                local tempIds = {};
                for i = 1, #node.lhs do
                    tempIds[i] = doScope:addVariable();
						
                    disableMetatableInfo(doScope, tempIds[i]);
                end
                local rewritten = {
                    Ast.LocalVariableDeclaration(doScope, tempIds, node.rhs)
                };
                for i, lhs in ipairs(node.lhs) do
                    local tempValue = Ast.VariableExpression(doScope, tempIds[i]);
                    if lhs.kind == AstKind.AssignmentVariable then
                        local localMetatableInfo = getLocalMetatableInfo(lhs.scope, lhs.id);
                        if localMetatableInfo then
                            local target = Ast.VariableExpression(lhs.scope, lhs.id);
                            target.__ignoreProxifyLocals = true;
                            local rawsetScope, rawsetId = data.scope:resolveGlobal("rawset");
                            data.scope:addReferenceToHigherScope(rawsetScope, rawsetId);
                            rewritten[#rewritten + 1] = Ast.FunctionCallStatement(Ast.VariableExpression(rawsetScope, rawsetId), {
                                target,
                                Ast.StringExpression(localMetatableInfo.valueName),
                                tempValue,
                            });
                        else
                            rewritten[#rewritten + 1] = Ast.AssignmentStatement({lhs}, {tempValue});
                        end
                    else
                        rewritten[#rewritten + 1] = Ast.AssignmentStatement({lhs}, {tempValue});
                    end
					end
					
                local doBody = Ast.Block(rewritten, doScope);
                return Ast.DoStatement(doBody);
            elseif(#node.lhs == 1 and node.lhs[1].kind == AstKind.AssignmentVariable) then
                local variable = node.lhs[1];
                local localMetatableInfo = getLocalMetatableInfo(variable.scope, variable.id);
                if localMetatableInfo then
                    local args = shallowcopy(node.rhs);
                    local vexp = Ast.VariableExpression(variable.scope, variable.id);
                    vexp.__ignoreProxifyLocals = true;
                    args[1] = localMetatableInfo.setValue.constructor(vexp, args[1]);
                    self.emptyFunctionUsed = true;
                    data.scope:addReferenceToHigherScope(self.emptyFunctionScope, self.emptyFunctionId);
                    return Ast.FunctionCallStatement(Ast.VariableExpression(self.emptyFunctionScope, self.emptyFunctionId), args);
                end
            end
        end
    end, function(node, data)

        if(node.kind == AstKind.LocalVariableDeclaration) then
            for i, id in ipairs(node.ids) do
                local expr = node.expressions[i] or Ast.NilExpression();
                local localMetatableInfo = getLocalMetatableInfo(node.scope, id);

                if localMetatableInfo then
                    local newExpr = self:CreateAssignmentExpression(localMetatableInfo, expr, node.scope);
                    node.expressions[i] = newExpr;
                end
            end
        end

        if(node.kind == AstKind.VariableExpression and not node.__ignoreProxifyLocals) then
            local localMetatableInfo = getLocalMetatableInfo(node.scope, node.id);

            if localMetatableInfo then
                data.scope:addReferenceToHigherScope(self.readHelperScope, self.readHelperId);
                return Ast.FunctionCallExpression(Ast.VariableExpression(self.readHelperScope, self.readHelperId), {
                    node,
                    Ast.StringExpression(localMetatableInfo.valueName),
                });
            end
        end

        if(node.kind == AstKind.AssignmentVariable) then
            local localMetatableInfo = getLocalMetatableInfo(node.scope, node.id);

            if localMetatableInfo then
                local vexp = Ast.VariableExpression(node.scope, node.id);
                vexp.__ignoreProxifyLocals = true;
                return Ast.AssignmentIndexing(vexp, Ast.StringExpression(localMetatableInfo.valueName));
            end
        end

        if(node.kind == AstKind.LocalFunctionDeclaration) then
            local localMetatableInfo = getLocalMetatableInfo(node.scope, node.id);

            if localMetatableInfo then
                local funcLiteral = Ast.FunctionLiteralExpression(node.args, node.body);
                local newExpr = self:CreateAssignmentExpression(localMetatableInfo, funcLiteral, node.scope);
                return Ast.LocalVariableDeclaration(node.scope, {node.id}, {newExpr});
            end
        end

        if(node.kind == AstKind.FunctionDeclaration) then
            local localMetatableInfo = getLocalMetatableInfo(node.scope, node.id);
            if(localMetatableInfo) then
                table.insert(node.indices, 1, localMetatableInfo.valueName);
            end
        end
    end)

    table.insert(ast.body.statements, 1, Ast.LocalVariableDeclaration(self.setMetatableVarScope, {self.setMetatableVarId}, {
        Ast.VariableExpression(self.setMetatableVarScope:resolveGlobal("setmetatable"))
    }));
end

return ProifyLocals;
