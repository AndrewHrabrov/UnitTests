#include <UnitTest++/UnitTest++.h>
#include <string>
#include "modAlphaCipher.h"
#include <locale>
#include <codecvt>

using convert_type = std::codecvt_utf8<wchar_t>;
std::wstring_convert<convert_type, wchar_t> converter;

SUITE(KeyTest) {
     TEST(ValidKey) {
        std::wstring wstr = modAlphaCipher(L"АМГ").encrypt(L"АРБУЗ");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("АЭДУФ", str);
     }
     
     TEST(LongKey) {
        std::wstring wstr = modAlphaCipher(L"АМГАМГАМГ").encrypt(L"АРБУЗ");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("АЭДУФ", str);
     }
     
     TEST(LowCaseKey) {
        std::wstring wstr = modAlphaCipher(L"амг").encrypt(L"АРБУЗ");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("АЭДУФ", str);
     }
     
     TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp(L"АМГ68"), modAlphaCipher_error);
     }
     
     TEST(PunctuationInKey) {
         CHECK_THROW(modAlphaCipher cp(L"АМГ.68"), modAlphaCipher_error);
     }
     
     TEST(SpaceInKey) {
         CHECK_THROW(modAlphaCipher cp(L"АМ Г"), modAlphaCipher_error);
     }
     
     TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(L""), modAlphaCipher_error);
    }
}

struct KeyB_fixture {
    modAlphaCipher * p;
    KeyB_fixture()
    {
        p = new modAlphaCipher(L"Б");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(encrypt) {
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        std::wstring wstr = p->encrypt(L"АЭРОФОТОСЪЁМКАЛАНДШАФТАУЖЕВЫЯВИЛАЗЕМЛИБОГАЧЕЙИПРОЦВЕТАЮЩИХКРЕСТЬЯН");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("БЮСПХПУПТЫЖНЛБМБОЕЩБХУБФЗЁГЬАГЙМБИЁНМЙВПДБШЁКЙРСПЧГЁУБЯЪЙЦЛСЁТУЭАО", str);
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        std::wstring wstr = p->encrypt(L"аэрофотосъёмкаландшафтаужевыявилаземлибогачейипроцветающихкрестьян");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("БЮСПХПУПТЫЖНЛБМБОЕЩБХУБФЗЁГЬАГЙМБИЁНМЙВПДБШЁКЙРСПЧГЁУБЯЪЙЦЛСЁТУЭАО", str);
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithSpaces) {
        CHECK_THROW(p->encrypt(L"АЭРОФОТОСЪЁМКА ЛАНДШАФТА УЖЕ ВЫЯВИЛА ЗЕМЛИ БОГАЧЕЙ И ПРОЦВЕТАЮЩИХ КРЕСТЬЯН."), modAlphaCipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithDigits) {
        CHECK_THROW(p->encrypt(L"АМГ68"), modAlphaCipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""), modAlphaCipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, NoLetters) {
        CHECK_THROW(p->encrypt(L"1234+8765=9999"), modAlphaCipher_error);
    }
    
    TEST(MaxShift) {
        std::wstring wstr = modAlphaCipher(L"Я").encrypt(L"АЭРОФОТОСЪЁМКАЛАНДШАФТАУЖЕВЫЯВИЛАЗЕМЛИБОГАЧЕЙИПРОЦВЕТАЮЩИХКРЕСТЬЯН");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("ЯЬПНУНСНРЩЕЛЙЯКЯМГЧЯУСЯТЁДБЪЮБЗКЯЖДЛКЗАНВЯЦДИЗОПНХБДСЯЭШЗФЙПДРСЫЮМ", str);
    }
}

SUITE(decrypt) {
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        std::wstring wstr = p->decrypt(L"БЮСПХПУПТЫЖНЛБМБОЕЩБХУБФЗЁГЬАГЙМБИЁНМЙВПДБШЁКЙРСПЧГЁУБЯЪЙЦЛСЁТУЭАО");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("АЭРОФОТОСЪЁМКАЛАНДШАФТАУЖЕВЫЯВИЛАЗЕМЛИБОГАЧЕЙИПРОЦВЕТАЮЩИХКРЕСТЬЯН", str);
    }
    
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        std::wstring wstr = p->decrypt(L"бюсПХПУПТЫЖНЛБМБОЕЩБХУБФЗЁГЬАГЙМБИЁНМЙВПДБШЁКЙРСПЧГЁУБЯЪЙЦЛСЁТУЭАО");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("АЭРОФОТОСЪЁМКАЛАНДШАФТАУЖЕВЫЯВИЛАЗЕМЛИБОГАЧЕЙИПРОЦВЕТАЮЩИХКРЕСТЬЯН", str);
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithSpaces) {
        CHECK_THROW(p->decrypt(L"БЮС ПХП УПТЫ ЖНЛБМБОЕЩБХУБФЗЁГЬАГЙМБИ ЁНМЙВПДБШЁКЙРСПЧГЁУБЯЪ ЙЦЛСЁТУЭАО"), modAlphaCipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithDigits) {
        CHECK_THROW(p->decrypt(L"БЮСПХПУПТЫЖНЛБМБОЕЩБХУБФЗЁГЬАГЙМБИЁНМЙВПДБШЁКЙРСПЧГЁУБЯЪЙЦЛСЁТУЭАО68"), modAlphaCipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, StringWithPunctuations) {
        CHECK_THROW(p->decrypt(L"БЮСПХПУПТЫЖНЛБМБОЕЩБХУБФЗЁГЬАГЙМБИЁНМЙВПДБШЁКЙРСПЧГЁУБЯЪЙЦЛСЁТУЭАО..."), modAlphaCipher_error);
    }
    
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""), modAlphaCipher_error);
    }
    
    TEST(MaxShift) {
        std::wstring wstr = modAlphaCipher(L"Я").decrypt(L"ЯЬПНУНСНРЩЕЛЙЯКЯМГЧЯУСЯТЁДБЪЮБЗКЯЖДЛКЗАНВЯЦДИЗОПНХБДСЯЭШЗФЙПДРСЫЮМ");
        std::string str = converter.to_bytes(wstr);
        CHECK_EQUAL("АЭРОФОТОСЪЁМКАЛАНДШАФТАУЖЕВЫЯВИЛАЗЕМЛИБОГАЧЕЙИПРОЦВЕТАЮЩИХКРЕСТЬЯН", str);
    }
    
}

int main()
{
    return UnitTest::RunAllTests();
}