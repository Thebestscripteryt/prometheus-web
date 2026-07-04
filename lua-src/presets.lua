-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- pipeline.lua
--
-- This Script Provides some configuration presets

return {
    ["Minify"] = {
        -- Default is LuaU for Roblox/Luau compatibility (string interpolation, +=, continue, etc.)
        LuaVersion = "LuaU";
        -- For minifying no VarNamePrefix is applied
        VarNamePrefix = "";
        -- Name Generator for Variables
        NameGenerator = "MangledShuffled";
        -- No pretty printing
        PrettyPrint = false;
        -- Seed is generated based on current time
        Seed = 0;
        -- No obfuscation steps
        Steps = {

        }
    };
    ["Weak"] = {
        -- Default is LuaU for Roblox/Luau compatibility (string interpolation, +=, continue, etc.)
        LuaVersion = "LuaU";
        -- For minifying no VarNamePrefix is applied
        VarNamePrefix = "";
        -- Name Generator for Variables that look like this: IlI1lI1l
        NameGenerator = "MangledShuffled";
        -- No pretty printing
        PrettyPrint = false;
        -- Seed is generated based on current time
        Seed = 0;
        -- Obfuscation steps
        Steps = {
            {
                Name = "Vmify";
                Settings = {
                    
                };
            },
            {
                Name = "ConstantArray";
                Settings = {
                    Treshold    = 1;
                    StringsOnly = true;
                }
            },
            {
                Name = "WrapInFunction";
                Settings = {

                }
            },
        }
    };
    ["Medium"] = {
        -- Default is LuaU for Roblox/Luau compatibility (string interpolation, +=, continue, etc.)
        LuaVersion = "LuaU";
        -- For minifying no VarNamePrefix is applied
        VarNamePrefix = "";
        -- Name Generator for Variables
        NameGenerator = "MangledShuffled";
        -- No pretty printing
        PrettyPrint = false;
        -- Seed is generated based on current time
        Seed = 0;
        -- Obfuscation steps
        Steps = {
            {
                Name = "WatermarkCheck";
                Settings = {
                    Content = "ObfuscatorHub Protection :: Discord https://discord.gg/WX2GXDJgSn :: Website https://obfuscatorhub.onrender.com/",
                };
            },
            {
                Name = "EncryptStrings";
                Settings = {

                };
            },
            {
                Name = "Vmify";
                Settings = {
                    
                };
            },
            {
                Name = "ConstantArray";
                Settings = {
                    Treshold    = 1;
                    StringsOnly = true;
                    Shuffle     = true;
                    Rotate      = true;
                    LocalWrapperTreshold = 0;
                }
            },
            {
                Name = "NumbersToExpressions";
                Settings = {

                }
            },
            {
                Name = "WrapInFunction";
                Settings = {

                }
            },
        }
    };
    ["Strong"] = {
        -- Default is LuaU for Roblox/Luau compatibility (string interpolation, +=, continue, etc.)
        LuaVersion = "LuaU";
        -- For minifying no VarNamePrefix is applied
        VarNamePrefix = "";
        -- Name Generator for Variables that look like this: IlI1lI1l
        NameGenerator = "MangledShuffled";
        -- No pretty printing
        PrettyPrint = false;
        -- Seed is generated based on current time
        Seed = 0;
        -- Obfuscation steps
        Steps = {
            {
                Name = "WatermarkCheck";
                Settings = {
                    Content = "ObfuscatorHub Protection :: Discord https://discord.gg/WX2GXDJgSn :: Website https://obfuscatorhub.onrender.com/",
                };
            },
            {
                Name = "ProxifyLocals";
                Settings = {
                    LiteralType = "string";
                }
            },
            {
                Name = "EncryptStrings";
                Settings = {

                };
            },
            {
                Name = "AntiTamper";
                Settings = {

                };
            },
            {
                Name = "Vmify";
                Settings = {
                    
                };
            },
            {
                Name = "ConstantArray";
                Settings = {
                    Treshold    = 1;
                    StringsOnly = true;
                    Shuffle     = true;
                    Rotate      = true;
                    LocalWrapperTreshold = 0;
                }
            },
            {
                Name = "NumbersToExpressions";
                Settings = {

                }
            },
            {
                Name = "WrapInFunction";
                Settings = {

                }
            },
        }
    };
    ["Ultra"] = {
    LuaVersion = "LuaU",
    VarNamePrefix = "",
    NameGenerator = "MangledShuffled",
    PrettyPrint = false,
    Seed = 0,
    Steps = {
        -- 1. Add vararg to all functions
        {
            Name = "AddVararg";
            Settings = {};
        },

        -- 2. Watermark check (optional – can comment out)
        {
            Name = "WatermarkCheck";
            Settings = {
                Content = "ObfuscatorHub Protection :: Discord https://discord.gg/WX2GXDJgSn :: Website https://obfuscatorhub.onrender.com/",
            };
        },

        -- 3. Split strings into tiny chunks (makes encryption harder)
        {
            Name = "SplitStrings";
            Settings = {
                Treshold = 1;               -- 100% of strings affected
                MinLength = 1;              -- shortest chunk = 1 char
                MaxLength = 6;              -- max chunk length (random)
                ConcatenationType = "custom"; -- most complex reassembly
                CustomFunctionType = "local"; -- each scope gets its own functions
                CustomLocalFunctionsCount = 5; -- multiple local functions per scope
            };
        },

        -- 4. Encrypt all strings (works on the chunks)
        {
            Name = "EncryptStrings";
            Settings = {}; -- no extra settings, uses default encryption
        },

        -- 5. Turn every number into an expression (must come before ConstantArray)
        {
            Name = "NumbersToExpressions";
            Settings = {
                Treshold = 1;            -- all numbers
                InternalTreshold = 0.1;  -- very low chance of using plain numbers (more nesting)
            };
        },

        -- 6. Extract all constants into an array (strings, numbers, booleans, nil)
        {
            Name = "ConstantArray";
            Settings = {
                Treshold = 1;               -- all constants
                StringsOnly = false;        -- include all types
                Shuffle = true;             -- random order
                Rotate = true;              -- rotate the array (with runtime fix)
                LocalWrapperTreshold = 1;   -- every function gets local wrappers
                LocalWrapperCount = 10;     -- 10 wrappers per scope
                LocalWrapperArgCount = 20;  -- each wrapper takes 20 args
                MaxWrapperOffset = 65535;   -- large offset range
                Encoding = "base64";        -- encode strings in base64
            };
        },

        -- 7. Proxify all locals (hide variable names behind metatables)
        {
            Name = "ProxifyLocals";
            Settings = {
                LiteralType = "any";        -- use random literal types (string, number, dict)
            };
        },

        -- 8. Anti‑tamper (your upgraded version)
        {
            Name = "AntiTamper";
            Settings = {
                UseDebug = true;           -- enable debug checks
                DiagnosticMode = false;    -- error on detection
            };
        },

        -- 9. Wrap everything in a function (multiple times for nesting)
        {
            Name = "WrapInFunction";
            Settings = {
                Iterations = 3;             -- wrap 3 times
            };
        },

        -- 10. VMify – the final compilation to custom bytecode
        {
            Name = "Vmify";
            Settings = {};
        },
    }
}
}
