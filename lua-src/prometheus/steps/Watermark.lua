

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");

local Watermark = Step:extend();
Watermark.Description = "This Step will add a watermark to the script";
Watermark.Name = "Watermark";

Watermark.SettingsDescriptor = {
  Content = {
    name = "Content",
    description = "The Content of the Watermark",
    type = "string",
    default = "This Script is Part of the Prometheus Obfuscator by Levno_710",
  },
  CustomVariable = {
    name = "Custom Variable",
    description = "The Variable that will be used for the Watermark",
    type = "string",
    default = "_WATERMARK",
  }
}

function Watermark:init(settings)

end

function Watermark:apply(ast)
  local body = ast.body;
  if string.len(self.Content) > 0 then
    local scope, variable = ast.globalScope:resolve(self.CustomVariable);
    local watermark = Ast.AssignmentVariable(ast.globalScope, variable);

    local content = self.Content;
    local len = string.len(content);
    local pieceCount = math.min(len, math.random(2, 4));
    local cuts = {};
    for i = 1, pieceCount - 1 do
      cuts[i] = math.random(1, len - 1);
    end
    table.sort(cuts);

    local valueExpression;
    local pos = 1;
    for i = 1, pieceCount do
      local cutEnd = cuts[i] or len;
      if cutEnd < pos then cutEnd = pos; end
      local piece = Ast.StringExpression(string.sub(content, pos, cutEnd));
      valueExpression = valueExpression and Ast.StrCatExpression(valueExpression, piece) or piece;
      pos = cutEnd + 1;
    end

    local statement = Ast.AssignmentStatement({
      watermark
    }, {
      valueExpression
    });

    table.insert(ast.body.statements, 1, statement)
  end
end

return Watermark;
