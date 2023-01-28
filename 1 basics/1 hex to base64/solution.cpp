#include "iostream"
#include "string"
#include "bitset"
#include "vector"
#include "tuple"
#include "stdlib.h"

#define PADDING 64;

enum base64_operation {
    encode,
    decode
};

class Util {
    public:
        static std::string hex_to_ascii(std::string input_string);
};

std::string Util::hex_to_ascii(std::string input_string) {
    if (input_string.length() % 2 != 0) throw std::invalid_argument("string is not hex");
    std::string plaintext {""};

    // iterate over the string in blocks of 2 chars to get hex, then convert to char
    for (auto i = 0; i < input_string.length(); i += 2) {
        std::string hex = "0x" + input_string.substr(i, 2);
        unsigned int ascii = std::stoul(hex, nullptr, 16);
        plaintext.push_back(char(ascii));
    }

    return plaintext;
}

class Base64 {
    public:
        static std::string get_char_table();
        static std::string encode(std::string plaintext);
        static std::string decode(std::string ciphertext);
};

std::string Base64::get_char_table() {
    return std::string {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="};
}

std::string Base64::encode(std::string plaintext) {
    std::string ciphertext {""};
    std::string char_table = Base64::get_char_table();

    // iterate over the plaintext in blocks of 3 chars
    // input: 3 chars * 8 bytes = 24 bits
    // base64 is 6 bits per char not 8 bits
    // output: 24 bits / 6 bits = 4 chars
    auto end = plaintext.length();
    for (auto i = 0; i < end; i += 3) {
        std::bitset<8> bits;
        std::uint8_t b1, b2, b3, b4;

        // 01001001 00100111 01101101
        // 010010|010010|011101|101101
        // 010010 010010 011101 101101
        // 18-18-29-45

        // each byte ->
        // start w/all 0s
        // | gives us any set value
        // & gives us the ability to ONLY give us values where BOTH are set
        // 0x3f is 63, which means we will only ever set 6 bits :thumbsup:
        // 00100111
        // | plaintext[i+1] >> 4;  // want last 2 c1  + first 4 of c2

        b1 = plaintext[i] >> 2;
        if (i+1 >= end) {
            b2 = (plaintext[i] << 4) & 0x3f;
            b3 = PADDING;
            b4 = PADDING;
        } else if (i+2 >= end) {
            b2 = ((plaintext[i] << 4) | plaintext[i+1] >> 4) & 0x3f; 
            b3 = (plaintext[i+1] << 2) & 0x3f;
            b4 = PADDING;
        } else {
            b2 = ((plaintext[i] << 4) | plaintext[i+1] >> 4) & 0x3f;
            b3 = ((plaintext[i+1] << 2) | plaintext[i+2] >> 6) & 0x3f;
            b4 = plaintext[i+2] & 0x3f;
        }

        ciphertext.push_back(char_table[b1]);
        ciphertext.push_back(char_table[b2]);
        ciphertext.push_back(char_table[b3]);
        ciphertext.push_back(char_table[b4]);
    }

    return ciphertext;
}

std::string Base64::decode(std::string ciphertext) {
    std::string plaintext {""};
    std::string char_table = Base64::get_char_table();
    if (ciphertext.length() % 4 != 0) throw std::invalid_argument("invalid base64 string");

    for (auto i = 0; i < ciphertext.length(); i += 4) {
        // impossible to not have at least 4 char, or it's an invalid base64 string
        std::size_t b1 = char_table.find(ciphertext[i]);
        std::size_t b2 = char_table.find(ciphertext[i+1]);
        std::size_t b3 = char_table.find(ciphertext[i+2]);
        std::size_t b4 = char_table.find(ciphertext[i+3]);

        // drop padding
        if (b3 == 64) b3 = 0;
        if (b4 == 64) b4 = 0;

        char c1, c2, c3;
        
        c1 = (b1 << 2) | b2 >> 4;
        c2 = (b2 << 4) | b3 >> 2;
        c3 = (b3 << 6) | b4;

        plaintext.push_back(char(c1));
        // drop padding
        if (b3 != 0) plaintext.push_back(char(c2));
        if (b4 != 0) plaintext.push_back(char(c3));
    }

    return plaintext;
}

bool run_tests() {
    // initialize all the shit
    bool tests_passed = true;
    std::vector<std::tuple<std::string, std::string, int>> test_cases;
    test_cases.push_back(std::tuple<std::string, std::string, int>("a",        "YQ==",     base64_operation::encode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("ab",       "YWI=",     base64_operation::encode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("abc",      "YWJj",     base64_operation::encode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("abcd",     "YWJjZA==", base64_operation::encode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("abcde",    "YWJjZGU=", base64_operation::encode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("abcdef",   "YWJjZGVm", base64_operation::encode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("YQ==",     "a",        base64_operation::decode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("YWI=",     "ab",       base64_operation::decode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("YWJj",     "abc",      base64_operation::decode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("YWJjZA==", "abcd",     base64_operation::decode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("YWJjZGU=", "abcde",    base64_operation::decode));
    test_cases.push_back(std::tuple<std::string, std::string, int>("YWJjZGVm", "abcdef",   base64_operation::decode));
    
    std::cout << "running tests..." << std::endl;

    for (auto &test_case : test_cases) {
        std::string input = std::get<0>(test_case);
        std::string expected = std::get<1>(test_case);
        bool operation = std::get<2>(test_case);
        std::string operation_name = (operation) ? "decoding" : "encoding";
        std::string actual;
        
        if (operation == base64_operation::encode) {
            actual = Base64::encode(input);
        } else {
            actual = Base64::decode(input);
        }
        
        std::cout << "TEST ";
        if (actual == expected) {
            std::cout << "PASS";
        } else {
            std::cout << "FAIL... " << operation_name << " " << input << std::endl; 
            std::cout << "    > expected: " << expected << std::endl;
            std::cout << "    > actual  : " << actual;
            tests_passed = false;
        }
        std::cout << std::endl;
    }

    return tests_passed;
}

int main() {
    std::string hex_input_string {"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"};
    std::string expected_base64_ciphertext {"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"};
    std::string actual_base64_ciphertext;
    std::string result;
    bool is_match = false;

    try {
        std::string plaintext = Util::hex_to_ascii(hex_input_string);
        actual_base64_ciphertext = Base64::encode(plaintext);
        std::string decoded_plaintext = Base64::decode(actual_base64_ciphertext);

        std::cout << "hex_input_string:           " << hex_input_string << std::endl;
        std::cout << "expected_base64_ciphertext: " << expected_base64_ciphertext << std::endl;
        std::cout << "actual_base64_ciphertext:   " << actual_base64_ciphertext << std::endl;
        std::cout << "expected_plaintext:         " << plaintext << std::endl;
        std::cout << "decoded_plaintext:          " << decoded_plaintext << std::endl;
        std::cout << "ciphertext matches:         ";
        if (expected_base64_ciphertext == actual_base64_ciphertext) std::cout << "yes";
        else std::cout << "no";
        std::cout << std::endl;
        std::cout << "plaintext matches:          ";
        if (plaintext == decoded_plaintext) std::cout << "yes";
        else std::cout << "no";
        std::cout << std::endl;

        run_tests();

        return is_match;
    } catch (const std::exception& ex) {
        std::cerr << "Error occurred: " << ex.what() << std::endl;
        return 1;
    }
}