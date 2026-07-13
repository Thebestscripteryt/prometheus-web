-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- lzw.lua
--
-- A small, self-contained LZW (Lempel-Ziv-Welch) compressor/decompressor,
-- operating on raw byte strings. LZW is a well-known, public-domain
-- algorithm (no license concerns); this is a fresh implementation written
-- for Prometheus, not derived from any third-party codebase.
--
-- Used by ConstantArray to compress the combined blob of extracted string
-- constants before base64-encoding it, since SplitStrings tends to produce
-- many small, highly repetitive fragments - exactly the kind of data LZW
-- is good at shrinking, even though the fragments barely compress on their
-- own individually.
--
-- The compressor (below) runs at obfuscation time, in this Lua process.
-- A separate, hand-written decompressor (see lzwDecodeSource below) gets
-- embedded as generated Lua source into the obfuscated output, so it can
-- run standalone under plain Lua 5.1/LuaU with no dependency on this file.

local lzw = {};

-- Compresses a byte string into a list of integer codes.
-- Standard LZW: start with a 256-entry dictionary (one per byte value),
-- greedily extend the current match by one byte at a time, emit a code
-- whenever the match is no longer in the dictionary, and add the extended
-- match as a new dictionary entry.
function lzw.compress(input)
    local dictionary = {};
    for i = 0, 255 do
        dictionary[string.char(i)] = i;
    end
    local dictSize = 256;

    local result = {};
    local resultLen = 0;
    local w = "";

    for i = 1, #input do
        local c = string.sub(input, i, i);
        local wc = w .. c;
        if dictionary[wc] then
            w = wc;
        else
            resultLen = resultLen + 1;
            result[resultLen] = dictionary[w];
            dictionary[wc] = dictSize;
            dictSize = dictSize + 1;
            w = c;
        end
    end

    if w ~= "" then
        resultLen = resultLen + 1;
        result[resultLen] = dictionary[w];
    end

    return result;
end

-- Decompresses a list of integer codes (as produced by lzw.compress) back
-- into the original byte string. Provided for testing/round-trip
-- verification in Lua; the actual runtime decompressor embedded in
-- obfuscated output is the generated source in lzwDecodeSource, which
-- implements the exact same algorithm directly as Lua source text.
function lzw.decompress(codes)
    local dictionary = {};
    for i = 0, 255 do
        dictionary[i] = string.char(i);
    end
    local dictSize = 256;

    local resultParts = {};
    local resultLen = 0;

    local w = dictionary[codes[1]];
    if w == nil then
        return "";
    end
    resultLen = resultLen + 1;
    resultParts[resultLen] = w;

    for i = 2, #codes do
        local k = codes[i];
        local entry;
        if dictionary[k] then
            entry = dictionary[k];
        elseif k == dictSize then
            entry = w .. string.sub(w, 1, 1);
        else
            error("Invalid LZW code: " .. tostring(k));
        end

        resultLen = resultLen + 1;
        resultParts[resultLen] = entry;

        dictionary[dictSize] = w .. string.sub(entry, 1, 1);
        dictSize = dictSize + 1;

        w = entry;
    end

    return table.concat(resultParts);
end

-- Lua source for a standalone runtime decompressor, meant to be parsed and
-- spliced into the obfuscated output by ConstantArray. Operates on a table
-- of integer codes (the variable `CODES`) and produces the original string.
-- This mirrors lzw.decompress above exactly - keep the two in sync.
lzw.decodeSource = [==[
do
    local dictionary = {};
    for i = 0, 255 do
        dictionary[i] = string.char(i);
    end
    local dictSize = 256;

    local parts = {};
    local partsLen = 0;

    local codes = CODES;
    local w = dictionary[codes[1]];
    partsLen = partsLen + 1;
    parts[partsLen] = w;

    for i = 2, #codes do
        local k = codes[i];
        local entry;
        if dictionary[k] then
            entry = dictionary[k];
        else
            entry = w .. string.sub(w, 1, 1);
        end

        partsLen = partsLen + 1;
        parts[partsLen] = entry;

        dictionary[dictSize] = w .. string.sub(entry, 1, 1);
        dictSize = dictSize + 1;

        w = entry;
    end

    RESULT = table.concat(parts);
end
]==];

return lzw;
