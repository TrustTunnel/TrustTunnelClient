#include <chrono>
#include <common/utils.h>
#include <gtest/gtest.h>
#include <net/quic_utils.h>
#include <net/tls.h>
#include <ngtcp2/ngtcp2.h>
#include <thread>

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
static int parse_hex_char(int c) {
    if (c >= '0' && c <= '9') {
        return c - 0x30;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 0x57;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 0x37;
    }
    return -1;
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

static std::vector<uint8_t> decode_from_hex(std::string_view hex) {
    if (hex.size() & 1) {
        return {};
    }
    std::vector<uint8_t> result;
    result.reserve(hex.size() >> 1);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = parse_hex_char(hex[i]);
        int lo = parse_hex_char(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return {};
        }
        result.push_back((uint8_t) (hi << 4 | lo));
    }
    return result;
}

TEST(QuicUtilsTest, ExtractClientHello) {
    std::vector<uint8_t> draft34_pkt =
            decode_from_hex("c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
                            "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
                            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
                            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
                            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
                            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
                            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
                            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
                            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
                            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
                            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
                            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
                            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
                            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
                            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
                            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
                            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
                            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
                            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
                            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
                            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
                            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
                            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
                            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
                            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
                            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
                            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
                            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
                            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
                            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
                            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
                            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
                            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
                            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
                            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
                            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
                            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
                            "e221af44860018ab0856972e194cd934");
    std::vector<uint8_t> google_mangled_pkt =
            decode_from_hex("c300000001089714ce4dc712435c000045349815f4232d1334276442f35"
                            "fa3505fa9fbbafc0d57c8e502d00ff976b3acc29aeaecb9ac05f9861fc75cf6c"
                            "4656b818abecce1475d238c7caef9d0a88c9bc8b45663d79972659808ec72f8e"
                            "e85dc903c3bcbf37267a7e3a96ab3d454ba77585dc39b90bdd19c76beee20cfb"
                            "dd929fb7c7da5664326811139e9dc891af87f19c497cf18b4b4de4c6fe2b4e96"
                            "270c9e2ec0822837a47228e3832677249e30b0f592333d7f7a4becbf74dc461e"
                            "2acf6f1278f7da5b804a951dae714382e7cbfde731213c92c59b2220d3911d7f"
                            "2daa31cc60779e9971e4a9814d510d83a79a66f1a9731cd8df40f01012c629a8"
                            "97e392c83bb2464c2c54141a5310868d00ae0a60ea95232769681c64c95d5599"
                            "00542dbe0bbacc242952fd5cbe42ba69689b4e9e3c1fe639f6e1e2d50e7b13f4"
                            "295c56eaec82bb14eb1bc9390c045e4e0e97b8ebe93cd5a20dd7cd83c6de5cd5"
                            "9210f9c33f7ee874e450c478ea4a359ff00a8286f7ac1f18a4b2af0ffc942725"
                            "af362a817dd92a1dbc9fddeb2c1d5c7dff05a4c985c78b02e35466d3b36a28d5"
                            "a9ce1eea14f215f431051663e88e7cd7e6c36f90d45a21a97c3b8e7705c95f72"
                            "f99c6dc4af04690582a57ff50bc3762f15dfa71322db1ce1aabe8c298455aec9"
                            "a644bccaa9347a9d186ec2801512ed827818cf3eba0781bdf09114d677acdbd0"
                            "665f5e5cbb79219488b742d37085de9079e51e92ffec7d2c7fcb2d3e02303dad"
                            "4eda0154cdd3c9f5f95c1533358d3299d7255c16e862276c4dea10667522c771"
                            "d5dca113fe03421e7e89ccddf44c3926163f5a40685b8f85b6f139b334b1f40e"
                            "d42235b9d9df77070f40ff9d8382e3338249a86c799e7748dc8ac74035584d23"
                            "e6c487fb3c5a36bdaae76fd2929a7ca43c064bfdcde5cd1b51f32cca66f27f19"
                            "b79dbf76d888afc47d313b476f5d4765f92f81becd996b36c5845eaef3f2b602"
                            "296ff7885cba127fcb2c161ffd87e4c32229c8e287de99699500ac2f8a8484a5"
                            "2b6f143cb429f36f73a2499f32896730da7b2c816256142daf623d28199ba9a6"
                            "4619205d6bca37e2fa2c201690607039589a314c305fe1d543647dacd252c8b9"
                            "d0c19cbf12d35157159d56da33c4c78925fcd4c516eb98b35ea80ad96198cc35"
                            "cdf817e917b99a82dc0e72482ca213c249b928017ccf73d3322ee021b84d6275"
                            "04312eae53d899bf6c5db3a4e9565428be6256e11c1e03fa2b603c810687f8cc"
                            "5a473d97bae95c82b26645d8e6e5b207545e6709ed649f6782626a61d48e2c6c"
                            "9d3c167f95fcf15596278fb5b715d6e6e7f50bee7af25580ff36fd174d9d2b61"
                            "e23c1a59bcd4509d6d169d12304c08827e298b5d3fdd85b8af0a7658e5c480b7"
                            "2ba20b79a09e5667091e52d587d44b1987e2c0c78f99ab5d4cbba87ba02eaaf7"
                            "aa9aa344c98163b6d11373a88c999737b29fbe8647077000903097417366c615"
                            "30802b1ee8224ea343c686226277300c446bc7266c70c9c66aba23764d7387d4"
                            "5241d3981854f6d97d3a7ab49c271e28128b13fa5f4a38647056a18ba6b2f90f"
                            "4432fd58e5d4fd5233a4c5087e5f904ba7dfb2b5074ee27578f78d24f180be5a"
                            "b4f480e0e93f5d20e594730eae7fd2a1fab7c306530d4c6b590a52ae15f270a0"
                            "b6e65075e63b0b6d1f6ca7770caa1ce698e15e9b2867292ddeb820c1fa926028"
                            "92d0469126e5a2f7d4e5c99f6b6afcc3097f06e47acc93454ba83e3250741860"
                            "3cbdb338b39c35b4703dfb016aeb2d57dce036e6261999e28778b89089b9370d"
                            "699046673647ed84f9a5271cd5ef73c09870d955b37b464ef6a8d79e8d7bb301"
                            "5f17e869fa064dde2cbc9f38e58a0116a9b148b6ef56796d72e1994d1bfc1060"
                            "44d00d350ffb602fc");

    std::vector<uint8_t> vk_packet = decode_from_hex(
            "ca0000000114f5acaf8f2893d252a7d967f54a867553a40dbfd90040407371b946905c69549c84e93e8de0e3bc64752b580a87303f"
            "545719c1ef3153e42a7a7f6c4115e241f62ebc739cce85082a9f0fcefdd8e45a33fe7aceb8dd6de6448354baf2bc20834b941cf12d"
            "8c33ca60c2682719aca2db4d0be217a7846441d910cf04c82d664f4a9d15bc354769466036f5bc9a5dc53abb425edf3001e6f8a979"
            "1e4cd0375d9d693ef32d7227c1b2447558b45cf81d18e32bf5e8588274cb172ea39f88b350e6d0b2a6446d12049e991c144190ab56"
            "e81920b3236ed519c81b7c2f9eb02c058d43d609e6dac6ed7d074faac82599e83181caaa5c29f3fae4b76520a1c99899bb9b117e19"
            "9217ef5744c1e7a0c03e0e05a88b939d965492ca964b35799eab89669273c989feca1d3abe837a84a2ba78b9ab85f99b50b92cbc8b"
            "e17af5933e12b7e367304039c6c06312036e29ccf67e97b913cb63253c5e15e2766a700f3ba34f1a8fd9af8c8228dcfd5b0da4c582"
            "7042d612b9e30307f37aaab5506c3d4d9440fa9827b8a8759a35248838cfb130bdfd5f7efef1ae46ddd22207ca2714807c30a1b208"
            "c980b7fe5dc192751a6d9dfa40dcafe573b89907c4a8235502b98ad70157f0a494bed6c424bce8421090b82f4faa5c8533a4c5f6f5"
            "cfda1bd749dba499915284106b39e8f2251c8be42f4ba7926c8f20901d9e329755d4be9582317dbe514b09b1eb8382b702be94462b"
            "506592dcff43b79d09d2f62117013f15a0f8226e9e092679607de92a9d9b801eb270ffefd35ea370ef3e7b34215e730614e7b81950"
            "1def26c61f0b51a837f955e267e31afa4105aa4a1b257dea346d3dc1f1bdfe1afcfcd7a97ff2d1ac2ed2c9026746154668ac9740a0"
            "bd9bc1c04b68efb6a5ceb181b3b3f7e7de1a13bc2e16c45ad7f01531cc0670bc00ac78a88bce9698c871f7b673f24dd67839d629c6"
            "a2e73025e37a0b238936330763ab304731a6e28a4b89e8117a9f383d55efedb3f6a0786e8fb1f94457e57aaea631c7a71b58180f79"
            "e45aa838ed0cbea402a4417a57890df6af504ed0c67a23f452e301262168504f549597b7558157127409a1dc9a133f2ff3aa08e8d1"
            "d2531ec82a4efa81c47fc994c5ef16062da9cbb831be02a7d06db3c323e8bc7ff31eeeccd9eec1e1a29753c9f5057b334c6da01121"
            "6e54284435209aebf5584b389a52f77d6f605a61258d0226d1ca40dd6665d70f90fa803bb3a857b8f41b15e4c8532a10766d761182"
            "2dfa9bb33eba4d0c632fc58d76cb2a15704b583793567508dc91024cee7e92dd439f7c0ec91e1623c5b23d005bb647c4b6e6808060"
            "0e2278dc48dc3f642ebebd08991d5294381a74f050b982d56680a97180636280db3b378e71f02d7df8ecdf7142e8f1fa113616f3d4"
            "31cc0447ed0360eebca0928741f8a81feffbee38b2814aaeef475af3256bf14bff6a1a1fe7febc03278b9d1edde1a54aaef6b69302"
            "cc1e515ddb1bfb9307ddfa26cc662b7493d2fe13af997ed08ab5542bf2fee6f5db7246e9d79f06469ac3915d3a1017ed4ae3dad7e9"
            "4bd9d40548f469929676d55ab2d881a71e3b0fb857d63da39a419352dacac88ac3ba2abca55fa9984fc1988fa6ce47899c0c672778"
            "084b94ffa988c165dad4e74d9c9720a1dc84c5f60d0ca5ab9b01986046a8542bfcd02d7ecfbb2e04db3f951676f8d1ccf729722de6"
            "b687ba2cfd19d0fd7f64adf75e6f30539aed88b699206250fb70b479ed4686");

    std::vector<uint8_t> safebrowsing_packet = decode_from_hex(
            "ce0000000108c7df6fadd25e8b6f00404600193962a345bfcad079bf3406322c05ff3526beaa674da2021a20d29d118ba39cd7b4ed"
            "84c4cfddf6c8ffadca0d5584b856ab38e33fd4aad145bf3dda6ae2fc6f3174a59b07447585f33f7d40a4ad85ffe38404c8dbda0e22"
            "19f6214b9de9d11d66aaba6f9efcb6fb4adc2a72632c17987e6547f386b92b6bfdab92dcff175c6f6ca4f554bd6ef2c64151b89b91"
            "af4a01ca86edb11fa0e5c5b92c8737cd1ab8ee70e0f708280f383a680342cc364f122adc05223fe3a0812b57a377914f74096bd5bf"
            "d3f461999e75bf2091d4141b3ddc9daa8a1c66b9e5776ddcea28a68f84f2c54d65cb65627948c280fd15896c1bf48eb383f7561b4d"
            "233ff9aaaafa436a00b9dadf7a0ed3c3d890bbd889235d13ef8fcac22ff12783b33917cfd3b59b2933bd5e138114b25b8fa873b3f9"
            "d8422ab52ae9ec5707410feffd27560f2ebff3281f61fd3e7c3f951c74a9213860b5b9fba5c290d18e2dbaa3b5abedc2ae5230bb92"
            "58b91126f5870f616c6d44884daf7105f45e96ee0eda46fd750cca468531862cb7ba609d8c70d91f571e818c4796e89cd144dc5790"
            "3df48467871e7f3dbaf799582dbcef01c0d76e268d9df6da65c37ee08b26553c7d8be6b2eb107ba1513490e85194debac7a38f269c"
            "9aa4768247555db9032e8c1bee70bf6d5aad88402daf4afa4fe4dda94d42abbe923ad16fc082b8fa5a1547e71eb1c38dd1fce77534"
            "996b457b2920ba666d496ebbbfb7cf4eafd3a1cd690dd1a9e50d9167bb92e6b315acb994528fd7cb7294b03c42c06c2d1f70bed9d1"
            "e9b9ac333ab7350ed4e106073784edb5dcefaf433d258059055ee727ceb88d8f25be0acc7d39f6bca482ad2488d8a4e46bc04f8696"
            "742e9357868be60af7cdce304fb8ff77dfc548c4b63587179070a9ce03ba4cff0e5d16f47ffa2570bcc843929215884650414e0c4f"
            "5ac07ae02bec12491708b74cfe503d25f4090ddc6ad0f743e9c5517fe41536e478d4b59bbf3ac16b3107adac123f633d1130c9b788"
            "59393393ec998b4a0b826293aaa39476964f30476dad0f4ccc94c1cf2d02a0181e438721c26082da956aa988c19d611d210edf7400"
            "e2f72fa99ad08e37f2cbacce08ec444b1d89c834c48ce4a8d4399a86eca184605323c3ee55eb08e9a5b1be61c11ddac4f9de3aca5b"
            "08851c37313e52f197dfa2caef3c3d926610f80291a7d1d160f5fd2a0074a91cf7abe729cadd8fd8d2aacdcd474c4cb68f870ea567"
            "c4338ee794598d380c546664375bc3770bb903bb3ed2596f567ee5669ccba97e182d0c2919a2e926d571a55b0239fcf98e3b821fde"
            "05852c76830eb3a48320d20bc22938046bc20b2c19b165fc017307c6d27d80857e9450da799766457e040c6eb514e5d68b5e74d83b"
            "a0303db5e45b90f711cc2536477cd927c71dfdc866992d49648f13e2dd697ff2c9457d8cadc9b858718f8ca591ed2611c2d9a5e165"
            "73702494ad2b291de771caa65c34b053c193ec1c89229b18b1963b4284066e8f7824ed63aa8e04f490579ea5947a924df1a44a7bfb"
            "996c3a73604f116ce5fae0064d3440fd643596bb8846ef006611734b446088e5306b9d4c089930d80d4a5d3c48904ea88b528f7914"
            "cb1afe9375e51943a901623b8cc6e6693a644e12d47bff95c5d3c83377a0a2e720101421a81a020c9848ffd305546e3dcfbe35ee4b"
            "8cac7f2f1703c92d7f20a4");

    std::vector<uint8_t> firefox_packet = decode_from_hex("ca0000000108"
                                                          "12eaff04b863530703ea5f00004248d1"
                                                          "8a40444ffb4f96e6b73a747bd550f36a"
                                                          "918aab05ec335f55867dfe7f07e30ba1"
                                                          "d2f2649d76705f8aaf3a0cf5d7201b93"
                                                          "aab9f1ea2a4ae05b9e5bf6bfe78cdae0"
                                                          "cf871d2906d1e79eaf18edc92dbf731c"
                                                          "a5ea1a2296d4b441a69fc2f9041358c9"
                                                          "bfab0d6b94a093333de8bef5bfba0135"
                                                          "2211ce4734310f217ef59cb3dd0e4fea"
                                                          "9ee52b15c0c7c7310eace6be73a37241"
                                                          "a96dd4a9a3ea3d20e3975b74bf13e68e"
                                                          "53562cf0b5c54943bf786f385133912a"
                                                          "855ede1e26f7104aa4a9485355284795"
                                                          "5a499ac063a328de6d7023207f25466e"
                                                          "6bb79b21f4003ec5eb89f37c8276a83c"
                                                          "0a693f8b5a96f3088ae83f2b8f2c8f83"
                                                          "a70ead8de1f532196faf56cc02d983ae"
                                                          "da05c24f35f48f6ac647304adad10b23"
                                                          "427a33c940359b598e4b4bbf73a0267a"
                                                          "41fbe078b8a6c26c3437e226e581f4db"
                                                          "907ae994778a6f09f857ea7e1864177f"
                                                          "fab5b064b33704242a99fe8262053783"
                                                          "921dd147192219dd63555d04af846508"
                                                          "e212e1b174bbb521c5494cc75eb172e8"
                                                          "b40bdbe9e1326f96fa2bc188e50b780b"
                                                          "826d238070ebb6e0220602eda75ed6cc"
                                                          "4b0fa5e58258d90e2b0e1737136501b7"
                                                          "3af9e9e2e02174fa54763159762034b9"
                                                          "93f696eadfbb77f60d823ce6039ceb15"
                                                          "321f09d1bb3caa93aae596b20b8b3b93"
                                                          "c6fe636f4cd074718227354f8e2e5b4e"
                                                          "2e07d24ed0a6c97aaa6460a2de6ea5b6"
                                                          "2898e363e6bc1238b92beb5cf0bef76f"
                                                          "4d0abd5cac45dd5e7770d8cebe91d885"
                                                          "74c55ac993185192b7e1776239e1f7f7"
                                                          "1db71bbc92ce2381861a4f4f373e063c"
                                                          "1f78409fa4dde35cb4349e843125c29c"
                                                          "7fdf94c33c1035000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000000000000000000000"
                                                          "00000000000000");

    for (auto *p : {&draft34_pkt, &google_mangled_pkt, &vk_packet, &safebrowsing_packet, &firefox_packet}) {
        std::vector<uint8_t> &pkt = *p;

        // Extract data needed for decryption of initial packet
        auto hd = ag::quic_utils::parse_quic_header(ag::as_u8v(pkt));
        ASSERT_TRUE(hd);
        auto payload = ag::quic_utils::decrypt_initial({pkt.data(), pkt.size()}, *hd);

        ASSERT_TRUE(payload);
        ASSERT_GT(payload->size(), 0);
        ASSERT_LE(payload->size(), pkt.size());

        auto crypto_frames = ag::quic_utils::reassemble_initial_crypto_frames({payload->data(), payload->size()});
        ASSERT_TRUE(crypto_frames);
        ASSERT_GT(crypto_frames->size(), 6);

        ASSERT_EQ(0x01, crypto_frames.value()[0]);
        uint32_t crypto_frames_len =
                crypto_frames.value()[1] << 16 | crypto_frames.value()[2] << 8 | crypto_frames.value()[3];
        ASSERT_EQ(crypto_frames->size() - 4, crypto_frames_len);
        ASSERT_EQ(0x03, crypto_frames.value()[4]);
        ASSERT_EQ(0x03, crypto_frames.value()[5]);

        ag::TlsReader tls{};
        tls_input_hshake(&tls, crypto_frames->data(), crypto_frames->size());

        bool got_sni = false;
        bool stop = false;
        while (!stop) {
            switch (tls_parse(&tls)) {
            case ag::TlsParseResult::TLS_RCLIENT_HELLO_SNI:
                got_sni = true;
                [[fallthrough]];
            case ag::TlsParseResult::TLS_RERR:
            case ag::TlsParseResult::TLS_RMORE:
            case ag::TlsParseResult::TLS_RDONE:
                stop = true;
                break;
            default:
                continue;
            }
        }
        std::cout << "Hostname: " << tls.tls_hostname << '\n';
        ASSERT_TRUE(got_sni);
    }
}

TEST(QuicUtilsTest, ExtractClientHelloFailed) {
    std::vector<uint8_t> super_short_packet = decode_from_hex(
            "ce0000000108c7df6fadd25e8b6f00404600193962a345bfcad079bf3406322c05ff3526beaa674da2021a20d29d118ba39cd7b4ed"
            "84c4cfddf6c8ffadca0d5584b856ab38e33fd4aad145bf3dda6ae2fc6f3174a59b07447585");
    std::vector<uint8_t> &pkt = super_short_packet;

    auto hd = ag::quic_utils::parse_quic_header(ag::as_u8v(pkt));
    ASSERT_TRUE(hd);
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    auto payload = ag::quic_utils::decrypt_initial({pkt.data(), pkt.size()}, *hd);

    ASSERT_FALSE(payload);
}

TEST(QuicUtilsTest, ParseBadHeader) {
    std::vector<uint8_t> bad_packet = decode_from_hex("000000");
    auto hd = ag::quic_utils::parse_quic_header(ag::as_u8v(bad_packet));
    ASSERT_FALSE(hd);
}
