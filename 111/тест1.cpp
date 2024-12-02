#include <UnitTest++/UnitTest++.h>
#include "/home/stud/Лаба 3_ТИМП/111/modAlphaCipher.h"
#include "/home/stud/Лаба 3_ТИМП/111/modAlphaCipher.cpp"


SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("БВГБВ", modAlphaCipher("АБВ").encrypt("БББББ"));
    }
    TEST(LongKey) {
        CHECK_EQUAL("БВГДЕ",modAlphaCipher("АБВГДЕЁЖ").encrypt("БББББ"));
    }
    TEST(LowCaseKey) {
        CHECK_EQUAL("БВГБВ", modAlphaCipher("абв").encrypt("БББББ"));
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp("Б1"), cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp("А,Б"), cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp("А Б"), cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(""), cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher cp("ААА"), cipher_error);
    }
}
struct KeyB_fixture {
    modAlphaCipher* p;
    KeyB_fixture()
    {
        p = new modAlphaCipher("Б");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};
SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ТПМОЧЁ", p->encrypt("СОЛНЦЕ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("ТПМОЧЁ", p->encrypt("солнце"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("ТПМОЧЁ", p->encrypt("Солнце"));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(""), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt("123123123"), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("ПРИВПРИВ",modAlphaCipher("МЫ").encrypt("ГХЬЖГХЬЖ"));
    }
}
SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("СОЛНЦЕ", p->decrypt("ТПМОЧЁ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p -> decrypt("нБНБНЬМБСБНФ"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt("НБНБ НЬМБ СБНФ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p -> decrypt("123123123"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p -> decrypt("НБНБ,НЬМБСБНФ"), cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(""), cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("ЯВЩБДШ",modAlphaCipher("МЫ").decrypt("ЛЭЁЬРУ"));
    }
}
int main(int argc, char **argv)
{
    return UnitTest::RunAllTests();
}
