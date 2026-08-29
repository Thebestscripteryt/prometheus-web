

return {
    ["Minify"] = {

        LuaVersion = "LuaU";

        VarNamePrefix = "";

        NameGenerator = "MangledShuffled";

        PrettyPrint = false;

        Seed = 0;

        Steps = {

        }
    };
    ["Weak"] = {

        LuaVersion = "LuaU";

        VarNamePrefix = "";

        NameGenerator = "MangledShuffled";

        PrettyPrint = false;

        Seed = 0;

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

            {
                Name = "Vmify";
                Settings = {

                };
            },
        }
    };
    ["Medium"] = {

        LuaVersion = "LuaU";

        VarNamePrefix = "";

        NameGenerator = "MangledShuffled";

        PrettyPrint = false;

        Seed = 0;

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

            {
                Name = "Vmify";
                Settings = {

                };
            },
        }
    };
    ["Strong"] = {

        LuaVersion = "LuaU";

        VarNamePrefix = "";

        NameGenerator = "MangledShuffled";

        PrettyPrint = false;

        Seed = 0;

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

            {
                Name = "AntiTamper";
                Settings = {};
            },

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

            {
                Name = "AddVararg";
                Settings = {};
            },

            {
                Name = "WatermarkCheck";
                Settings = {
                    Content = "ObfuscatorHub Protection :: Discord https://discord.gg/WX2GXDJgSn :: Website https://obfuscatorhub.onrender.com/",
                };
            },

            {
                Name = "MethodCallToIndex";
                Settings = {};
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
                    Treshold = 0.1;
                    MaxJunkStatements = 2;
                };
            },

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

            {
                Name = "EncryptStrings";
                Settings = {};
            },

            {
                Name = "NumbersToExpressions";
                Settings = {
                    Treshold = 1;
                    InternalTreshold = 0.3;
                };
            },

            {
                Name = "ProxifyLocals";
                Settings = {
                    LiteralType = "any";
                };
            },

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

            {
                Name = "JunkCodeInsertion";
                Settings = {
                    Treshold = 0.1;
                    MaxJunkStatements = 2;
                };
            },

            {
                Name = "WrapInFunction";
                Settings = {
                    Iterations = 1;
                };
            },

            {
                Name = "AntiTamper";
                Settings = {};
            },

            {
                Name = "Vmify";
                Settings = {};
            },
        }
    }
}
