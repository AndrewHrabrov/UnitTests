#include <UnitTest++/UnitTest++.h>
#include <string>
#include "table.h"
#include <locale>
#include <codecvt>

using convert_type = std::codecvt_utf8<wchar_t>;
std::wstring_convert<convert_type, wchar_t> converter;

SUITE(KeyTest) {
    TEST(ValidKey) {
        std::wstring wstr = tableCipher(4).encrypt(L"АРБУЗ");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("У Б Р АЗ", str);
    }
    
    TEST(LongKey) {
        std::wstring wstr = tableCipher(8).encrypt(L"АРБУЗ");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("   ЗУБРА", str);
    }
    
    TEST(EasyKey) {
        CHECK_THROW(tableCipher cp(1), tableCipher_error);
    }
    
    TEST(NegativeKey) {
        CHECK_THROW(tableCipher cp(-25), tableCipher_error);
    }
    
    TEST(ZeroKey) {
        CHECK_THROW(tableCipher cp(0), tableCipher_error);
    }
    
    TEST(BigKey) {
        CHECK_THROW(tableCipher cp(1001), tableCipher_error);
    }
}

struct KeyThree_fixture {
    tableCipher * p;
    KeyThree_fixture()
    {
        p = new tableCipher(3);
    }
    ~KeyThree_fixture()
    {
        delete p;
    }
};

SUITE(encrypt) {
    TEST_FIXTURE(KeyThree_fixture, UpCaseString) {
        std::wstring wstr = p->encrypt(L"АЭРОФОТОСЪЁМКА");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("РОСМ ЭФОЁААОТЪК", str);
    }
    
    TEST_FIXTURE(KeyThree_fixture, LowCaseString) {
        std::wstring wstr = p->encrypt(L"аэрофотосъёмка");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("росм эфоёааотък", str);
    }
    
    TEST_FIXTURE(KeyThree_fixture, StringWithSpacesNpunctuation) {
        std::wstring wstr = p->encrypt(L"АЭРОФОТОСЪЁМКА ЛАНДШАФТА УЖЕ ВЫЯВИЛА ЗЕМЛИ БОГАЧЕЙ И ПРОЦВЕТАЮЩИХ КРЕСТЬЯН.");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("РОСМ НААЖВВАЕИОЧ ПЦТЩ ЕЬ.ЭФОЁААШТУ ЯЛЗЛБАЙ ОЕЮХРТНАОТЪКЛДФ ЕЫИ М ГЕИРВАИКСЯ", str);
    }
    
    TEST_FIXTURE(KeyThree_fixture, StringWithDigits) {
        std::wstring wstr = p->encrypt(L"АМГ68");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("Г М8А6", str);
    }
    
    TEST_FIXTURE(KeyThree_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""), tableCipher_error);
    }
}

SUITE(decrypt) {
    TEST_FIXTURE(KeyThree_fixture, UpCaseString) {
        std::wstring wstr = p->decrypt(L"РОСМ ЭФОЁААОТЪК");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("АЭРОФОТОСЪЁМКА ", str);
    }
    
    TEST_FIXTURE(KeyThree_fixture, LowCaseString) {
        std::wstring wstr = p->decrypt(L"росм эфоёааотък");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("аэрофотосъёмка ", str);
    }
    
    TEST_FIXTURE(KeyThree_fixture, StringWithSpacesNpunctuation) {
        std::wstring wstr = p->decrypt(L"РОСМ НААЖВВАЕИОЧ ПЦТЩ ЕЬ.ЭФОЁААШТУ ЯЛЗЛБАЙ ОЕЮХРТНАОТЪКЛДФ ЕЫИ М ГЕИРВАИКСЯ");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("АЭРОФОТОСЪЁМКА ЛАНДШАФТА УЖЕ ВЫЯВИЛА ЗЕМЛИ БОГАЧЕЙ И ПРОЦВЕТАЮЩИХ КРЕСТЬЯН.", str);
    }
    
    TEST_FIXTURE(KeyThree_fixture, StringWithDigits) {
        std::wstring wstr = p->decrypt(L"6МА");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("АМ6", str);
    }
    
    TEST_FIXTURE(KeyThree_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""), tableCipher_error);
    }
}

int main()
{
    return UnitTest::RunAllTests();
}
