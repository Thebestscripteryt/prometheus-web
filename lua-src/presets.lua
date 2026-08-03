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
                Name = "MethodCallToIndex";
                Settings = {}
            },
            {
                Name = "ConstantArray";
                Settings = {
                    Treshold    = 1;
                    StringsOnly = true;
                    Encoding    = "xor";
                }
            },
            {
                Name = "WrapInFunction";
                Settings = {

                }
            },
            -- Vmify must run LAST: it compiles the current AST into a custom
            -- bytecode VM. Every other step should shape the *source logic*
            -- first; if a size/wrapper-adding step runs after Vmify, it ends up
            -- operating on the (already huge) compiled VM code instead of the
            -- original logic, multiplying output size and compile time instead
            -- of just adding to it.
            {
                Name = "Vmify";
                Settings = {

                };
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
                Name = "MethodCallToIndex";
                Settings = {}
            },
            {
                Name = "EncryptStrings";
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
                    Encoding    = "xor";
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
            -- Vmify must run LAST (see note in the Weak preset above).
            {
                Name = "Vmify";
                Settings = {

                };
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
                Name = "MethodCallToIndex";
                Settings = {}
            },
            {
                Name = "OpaquePredicates";
                Settings = {
                    Treshold = 1;
                };
            },
            {
                Name = "JunkCodeInsertion";
                Settings = {
                    Treshold = 0.15;
                    MaxJunkStatements = 3;
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
                Name = "ConstantArray";
                Settings = {
                    Treshold    = 1;
                    StringsOnly = true;
                    Shuffle     = true;
                    Rotate      = true;
                    LocalWrapperTreshold = 0;
                    Encoding    = "xor";
                }
            },
            {
                Name = "NumbersToExpressions";
                Settings = {

                }
            },
            {
                -- Second junk-code pass: EncryptStrings/ConstantArray above just
                -- generated a decrypt/decoder runtime. Running JunkCodeInsertion
                -- again here pollutes that generated runtime with dead branches
                -- too, instead of leaving it as the one clean, recognizable block
                -- in an otherwise junk-laden script.
                Name = "JunkCodeInsertion";
                Settings = {
                    Treshold = 0.15;
                    MaxJunkStatements = 3;
                };
            },
            {
                Name = "WrapInFunction";
                Settings = {

                }
            },
            -- Vmify must run LAST (see note in the Weak preset above).
            {
                Name = "Vmify";
                Settings = {

                };
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

            -- 2. Watermark check
            {
                Name = "WatermarkCheck";
                Settings = {
                    Content = "ObfuscatorHub Protection :: Discord https://discord.gg/WX2GXDJgSn :: Website https://obfuscatorhub.onrender.com/",
                };
            },

            -- 2.5. Convert method-call syntax (a:b()) into index+call syntax
            -- (a["b"](a)) so method names stop leaking in plaintext and get
            -- swept up by SplitStrings/EncryptStrings/ConstantArray below.
            -- Runs early so the temp locals it introduces also get
            -- proxified/opaque-predicated like the rest of the script.
            {
                Name = "MethodCallToIndex";
                Settings = {};
            },

            -- 3. Inject always-true arithmetic tautologies into if/while/repeat
            -- conditions. Runs early so its own generated number literals get
            -- the same downstream treatment (NumbersToExpressions, ConstantArray
            -- encoding, etc.) as the rest of the script instead of standing out.
            {
                Name = "OpaquePredicates";
                Settings = {
                    Treshold = 1;
                };
            },

            -- 3.5. Insert dead (never-executed) branches with fresh runtime-false
            -- conditions between statements. Kept conservative here (low
            -- Treshold, small MaxJunkStatements) since this preset already has
            -- a documented history of size/compile-time blowups from steps
            -- that multiply per-statement or per-scope.
            {
                Name = "JunkCodeInsertion";
                Settings = {
                    Treshold = 0.1;
                    MaxJunkStatements = 2;
                };
            },

            -- 4. Split strings into chunks (makes encryption harder).
            -- MaxLength raised from 6 -> 16 and CustomLocalFunctionsCount
            -- lowered from 5 -> 3: a MaxLength of 6 turns even short strings
            -- into a huge number of tiny chunks, each needing its own
            -- reassembly code. This was the single biggest driver of both
            -- output size and compile time; 16 keeps strings well-scrambled
            -- with dramatically less generated code.
            {
                Name = "SplitStrings";
                Settings = {
                    Treshold = 1;
                    MinLength = 1;
                    MaxLength = 16;
                    ConcatenationType = "custom";
                    CustomFunctionType = "local";
                    CustomLocalFunctionsCount = 3;
                };
            },

            -- 5. Encrypt all strings (works on the chunks)
            {
                Name = "EncryptStrings";
                Settings = {};
            },

            -- 6. Turn every number into an expression (must come before ConstantArray).
            -- InternalTreshold raised from 0.1 -> 0.3: 0.1 meant almost every
            -- number expression recursively nested into further sub-expressions,
            -- compounding size for very little extra protection.
            {
                Name = "NumbersToExpressions";
                Settings = {
                    Treshold = 1;
                    InternalTreshold = 0.3;
                };
            },

            -- 7. Proxify all locals (hide variable names behind metatables)
            {
                Name = "ProxifyLocals";
                Settings = {
                    LiteralType = "any";
                };
            },

            -- 8. Anti-tamper
            {
                Name = "AntiTamper";
                Settings = {
                    UseDebug = true;
                    DiagnosticMode = true;
                };
            },

            -- 9. Extract all constants into an array (strings, numbers, booleans, nil).
            -- LocalWrapperCount 10 -> 3, LocalWrapperArgCount 10 -> 5,
            -- MaxWrapperOffset 20000 -> 2000: these wrapper functions are
            -- generated PER SCOPE, so high counts multiply directly into
            -- output size and compile time across every function in the
            -- script. 3 wrappers of 5 args each still gives strong constant
            -- obfuscation without the runaway cost.
            {
                Name = "ConstantArray";
                Settings = {
                    Treshold = 1;
                    StringsOnly = false;
                    Shuffle = true;
                    Rotate = true;
                    LocalWrapperTreshold = 1;
                    LocalWrapperCount = 3;
                    LocalWrapperArgCount = 5;
                    MaxWrapperOffset = 2000;
                    Encoding = "xor";
                };
            },

            -- 9.5. Second junk-code pass: EncryptStrings/ConstantArray above
            -- just generated a decrypt/decoder + constant-array runtime.
            -- Running JunkCodeInsertion again here pollutes that generated
            -- runtime with dead branches too, instead of leaving it as the
            -- one clean, recognizable block in an otherwise junk-laden
            -- script. Kept at the same conservative settings as pass 1.
            {
                Name = "JunkCodeInsertion";
                Settings = {
                    Treshold = 0.1;
                    MaxJunkStatements = 2;
                };
            },

            -- 10. Wrap everything in a function.
            -- Iterations 3 -> 1: each extra iteration re-wraps the ENTIRE
            -- current output (already large from the steps above), so this
            -- setting alone was roughly tripling final size and compile time.
            {
                Name = "WrapInFunction";
                Settings = {
                    Iterations = 1;
                };
            },

            -- 11. Vmify must run LAST: it compiles the current AST into a
            -- custom bytecode VM. Every step above shapes the source logic
            -- first; if ConstantArray/WrapInFunction ran after Vmify (as they
            -- did in a previous version of this file), they'd operate on the
            -- already-compiled VM code instead of the original logic,
            -- multiplying size and compile time instead of just adding to it.
            -- (This re-ordering, done for a mistaken performance reason, was
            -- the actual root cause of the multi-hundred-thousand-percent
            -- size blowup and near-hangs on real scripts.)
            {
                Name = "Vmify";
                Settings = {};
            },
        }
    }
}
