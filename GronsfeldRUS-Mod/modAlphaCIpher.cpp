#include "modAlphaCipher.h"
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <stdexcept>

modAlphaCipher::modAlphaCipher(const std::wstring& skey) {
    for (unsigned i = 0; i < numAlpha.size(); i++) {
        alphaNum[numAlpha[i]] = i;
    }
    key = convert(getValidKey(skey));
}

std::wstring modAlphaCipher::encrypt(const std::wstring& open_text) {
    std::vector<int> work = convert(getValidText(open_text));
    for (unsigned i = 0; i < work.size(); i++) {
        work[i] = (work[i] + key[i % key.size()]) % alphaNum.size();
    }
    return convert(work);
}

std::wstring modAlphaCipher::decrypt(const std::wstring& cipher_text) {
    std::vector<int> work = convert(getValidText(cipher_text));
    for (unsigned i = 0; i < work.size(); i++) {
        work[i] = (work[i] + alphaNum.size() - key[i % key.size()]) % alphaNum.size();
    }
    return convert(work);
}

inline std::vector<int> modAlphaCipher::convert(const std::wstring& s) {
    std::vector<int> result;
    for (auto c : s) {
        result.push_back(alphaNum[c]);
    }
    return result;
}

inline std::wstring modAlphaCipher::convert(const std::vector<int>& v) {
    std::wstring result;
    for (auto i : v) {
        result.push_back(numAlpha[i]);
    }
    return result;
}


inline std::wstring modAlphaCipher::getValidKey(const std::wstring & s)
{
    std::wstring temp(s);
    
    if (s.empty()) {
        throw modAlphaCipher_error("Empty key! ");
    }
    
    std::locale loc("ru_RU.UTF-8");
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
    temp = codec.from_bytes(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(s));
    
    for (auto& v : temp) {
        v = std::toupper(v, loc);
        if (!isalpha(v, loc) || islower(v, loc)) {
            throw modAlphaCipher_error("Invalid key");
        }
    }
    return temp;
}

inline std::wstring modAlphaCipher::getValidText(const std::wstring & s)
{
    std::wstring temp(s);
    
    if (s.empty()) {
        throw modAlphaCipher_error("Empty text! ");
    }
    
    std::locale loc("ru_RU.UTF-8");
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
    temp = codec.from_bytes(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(s));
    
    for (auto &c : temp) {
        c = std::toupper(c, loc);
        if (!isalpha(c, loc) || islower(c, loc)) {
            throw modAlphaCipher_error("Invalid key");
        }
    }
    return temp;
}
