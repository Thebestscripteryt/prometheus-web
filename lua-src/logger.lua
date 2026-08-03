-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- logger.lua

local logger = {}
local config = require("config");
local colors = require("colors");

logger.LogLevel = {
	Error = 0,
	Warn = 1,
	Log = 2,
	Info = 2,
	Debug = 3,
}

logger.logLevel = logger.LogLevel.Log;

local function eprint(str)
	io.stderr:write(tostring(str) .. "\n");
end

logger.debugCallback = function(...)
	eprint(colors(config.NameUpper .. ": " .. table.concat({...}), "grey"));
end;
function logger:debug(...)
	if self.logLevel >= self.LogLevel.Debug then
		self.debugCallback(...);
	end
end

logger.logCallback = function(...)
	eprint(colors(config.NameUpper .. ": ", "magenta") .. table.concat({...}));
end;
function logger:log(...)
	if self.logLevel >= self.LogLevel.Log then
		self.logCallback(...);
	end
end

function logger:info(...)
	if self.logLevel >= self.LogLevel.Log then
		self.logCallback(...);
	end
end

logger.warnCallback = function(...)
	eprint(colors(config.NameUpper .. ": " .. table.concat({...}), "yellow"));
end;
function logger:warn(...)
	if self.logLevel >= self.LogLevel.Warn then
		self.warnCallback(...);
	end
end

logger.errorCallback = function(...)
	eprint(colors(config.NameUpper .. ": " .. table.concat({...}), "red"))
	error(...);
end;
function logger:error(...)
	self.errorCallback(...);
	error(config.NameUpper .. ": logger.errorCallback did not throw an Error!");
end


return logger;
