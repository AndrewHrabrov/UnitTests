#pragma once
#include <string>
#include <vector>
#include <stdexcept>

class tableCipher {
public:
    tableCipher(unsigned int columns); // Конструктор
    std::wstring encrypt(const std::wstring& sourcetext); 
    std::wstring decrypt(const std::wstring& ciphertext); 
    unsigned int getValidKey(unsigned int key);
    std::wstring getValidText(const std::wstring& text);
    std::wstring validCipher(const std::wstring& sourcetext, const std::wstring& ciphertext);

private:
    unsigned int columns; 
};

class tableCipher_error: public std::invalid_argument
{
public:
    explicit tableCipher_error (const std::string& what_arg):
        std::invalid_argument(what_arg) {}
    explicit tableCipher_error (const char* what_arg):
        std::invalid_argument(what_arg) {}
};
