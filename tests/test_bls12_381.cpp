// SPDX-License-Identifier: MIT
#include "test_framework.hpp"

#include <blst.h>

#include "crypto/bls12_381.hpp"

using namespace finalis;

namespace {

// Known answers from py_ecc 7.0.1 (Ethereum's Python BLS, independent of blst): G2ProofOfPossession
// with DST / POP_TAG set to crypto::kBlsTimeSignatureDst / kBlsPopDst, KeyGen on ikm = 32 x byte,
// message "time-signature-kat"; xi and the Lagrange-weighted aggregate over keys {0, 2, 3} computed
// from the McFly formulas in plain integer arithmetic mod r.
struct Kat {
  const char* ikm;
  const char* sk;
  const char* pk;
  const char* sig;
  const char* pop;
  const char* xi;
};
const Kat kKats[] = {
    {"0101010101010101010101010101010101010101010101010101010101010101",
     "144b27828e305a2d67fc7f4eea6de706b405cdd1ab8ad2daec046ccdeeec8b79",
     "95a254501b7733239ed3cec4d56737977bd09ede881d8a234560e83e5525017add3b1dcc3eabfb85e12a4131b19c253b",
     "8e257de3f3449dd54dcb3da04785707373e291b7fbf53c6f39c159f96800da3309f76bc572df1c1be7447243125b9e6702316fd97bb333a6fc36b9d5b761576913f445558122d640dbb5c9340f82172ca7213d4be075f78db7fbf0bdc51fb74f",
     "b2a97ec5941f2015687b71d0723803f28d83fc56c1141003c11130839bbbbfd282052494774a391af93078aa1fd7d26c0bff4d843d9d63b40a9cdb0da332636ca406922180e8a5ed66b0a996f394ee161968219d7844a7db746cb1d410c05392",
     "3fbda0fd0cd391784e16c92c9d662351e714826fc0f4000a790655ea0e2ab0a8"},
    {"0202020202020202020202020202020202020202020202020202020202020202",
     "1ff56eef5220c383a6522aa9a92776e3034bf1153839d54c9e3d2bcb6c04948e",
     "ac80a5e08c712d5f08f0306ad743f7d8c215d982489b84a1d6ba805733d94c006e8938f9089a75db3ffa135af33bc69a",
     "a77a3ca674b72664d421d2913174d908e0273f2d998673b195544304b18a08a1146512ac010327f3f04cfc7f3d83be2b1837f0c1b5952c4cabedfecbfd293fad12c57aef9c80ddc4b4560e4a146b183a42d19dc02fa7c92e53b0dd11f644ec51",
     "86cc596af5438c5aa4514e08d9a38732cfa011b89d78c58a64a70b2db460ec107914ca37d62c5dc19b01b6a3cf87ed77053f5ecc8ed88910026d62dc9a438cdae4cb43cd6debe047498b025b2ee9506ae0aeeecac5d917b40b018ba573935214",
     "1f93b51e8429b155a9d9ab9a3cbb04a4086b232c7869f397dda3f777ca0f5d2b"},
    {"0303030303030303030303030303030303030303030303030303030303030303",
     "70af5b11c1e57ab1ad314bf7178e5298a53d39922592216a21990e7e1293d0e2",
     "96df714a5cc9ddd2298546dce3d6d3827762a6d5b1c2a91e5ca93c9c898b1b4319cc105c493212a55b63080732ec2249",
     "85cfc17aae97b6fd9c3e70d65c235e38cdb1310f9df6bbec131534e06a556690cbb3fcd447b0159c77e1379d507259fa0bfe8abdda588f6ad1df1e0778931cf8f5c3643bec4fdf05c57955846cddc2516775aa17174109b5f10a4144d21baf27",
     "90b030fade913a5d74883e20cfdbae0bb06e13633c0a30caa0977a65485babab1906a2d17281de854e93fff8d6ec04b9033909aca21629d95ff3873d1efe9ee9b9cc1553a8d2f9a07579fc164a82a46917646b66144c8af622a8c0fa5d4d7ad1",
     "05903b0181befd5debad410822d28b2841a8ddf3124de57b90d194a804ba01b3"},
    {"0404040404040404040404040404040404040404040404040404040404040404",
     "47db882465dce1179503001f752877b84919f40a37b92f955aa527e5f7459a68",
     "95e05aea89db0e84b87ab96a0203cbff924f86a35494c9a9ce274b768fc555a6b761f2fc2b1b58d9cda73d4cdf4bca24",
     "97857d59a64b95d718d27b2c00fc278ac8789ea0369f5e27fcc5d25944983057d1b0956ff74ea40bf0c21a1fabebbcbd172308ddfe05566b7c2f22f358096264ddf36e99af611df789a87028aac444fe4c445d9a880804467ab53879a6b0ef98",
     "b005cff3e58f509e5897cdb04cd48dfb3e2c6e26f7c0de182f557177502ab3324cc561c7ff7bbb902a250d5b39845d31070b352f2eb52d5ad84c12984ccd8c9fc189bd0f07dadf1eb5ea40ee646db8e431c805690421db57cb121fe84a158298",
     "0031f23a3d3b8c41a4631110bd797fe13e8d70a509f97da022553562ad7e8f66"},
};
const char* kLagrange023[] = {"3df806b080497bd115ea60581e30601639bd2c3860ebfa18d879cfb3e5639403", "6bb40754e015740a8ffe74b588686d466da129158d4e3b733d20c0aa97f8e9d4", "3e2f40a0f2dc0ab4c08adb026caae2ae001cf2b811c28271ea656f9f82a3822c"};
const char* kAggregate023 = "8f3d266a55e49190199421d629d746291c8c956b227bbb20671adf8e4ca285e35dc180a0780b5d023aa3fde78695f0d611de9d8c14e2998d25603a68465dabe3c619e12103f18d5602ae214177f0929f1f2538e3f2ddae1890e2279d578e55be";

template <std::size_t N>
std::array<std::uint8_t, N> hex_array(const char* hex) {
  const auto b = hex_decode(hex);
  ASSERT_TRUE(b.has_value() && b->size() == N);
  std::array<std::uint8_t, N> out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

Bytes text(const char* s) { return Bytes(s, s + std::char_traits<char>::length(s)); }

crypto::BlsSecretKey kat_secret(const Kat& k) {
  const auto ikm = hex_decode(k.ikm);
  auto sk = crypto::bls_keygen(*ikm);
  ASSERT_TRUE(sk.has_value());
  return *sk;
}

blst_fr fr(const crypto::BlsScalar& b) {
  blst_scalar s;
  blst_scalar_from_bendian(&s, b.data());
  blst_fr f;
  blst_fr_from_scalar(&f, &s);
  return f;
}

bool fr_eq(const blst_fr& a, const blst_fr& b) {
  blst_scalar sa, sb;
  blst_scalar_from_fr(&sa, &a);
  blst_scalar_from_fr(&sb, &b);
  return std::equal(std::begin(sa.b), std::end(sa.b), std::begin(sb.b));
}

}  // namespace

TEST(test_bls_matches_py_ecc_known_answers) {
  for (const auto& k : kKats) {
    const auto sk = kat_secret(k);
    ASSERT_EQ(hex_encode(Bytes(sk.bytes.begin(), sk.bytes.end())), std::string(k.sk));
    const auto pk = crypto::bls_public_key(sk);
    ASSERT_TRUE(pk.has_value());
    ASSERT_TRUE(*pk == hex_array<48>(k.pk));
    const auto sig = crypto::bls_sign(sk, text("time-signature-kat"), crypto::kBlsTimeSignatureDst);
    ASSERT_TRUE(sig.has_value());
    ASSERT_TRUE(*sig == hex_array<96>(k.sig));
    const auto pop = crypto::bls_pop_prove(sk);
    ASSERT_TRUE(pop.has_value());
    ASSERT_TRUE(*pop == hex_array<96>(k.pop));
    const auto xi = crypto::mcfly_evaluation_point(*pk);
    ASSERT_TRUE(xi.has_value());
    ASSERT_TRUE(*xi == hex_array<32>(k.xi));
  }
}

TEST(test_bls_verify_rejects_wrong_message_key_dst_and_pop_misuse) {
  const auto sk0 = kat_secret(kKats[0]);
  const auto pk0 = hex_array<48>(kKats[0].pk);
  const auto pk1 = hex_array<48>(kKats[1].pk);
  const auto sig = hex_array<96>(kKats[0].sig);
  const auto pop = hex_array<96>(kKats[0].pop);
  ASSERT_TRUE(crypto::bls_verify(pk0, text("time-signature-kat"), crypto::kBlsTimeSignatureDst, sig));
  ASSERT_TRUE(!crypto::bls_verify(pk0, text("time-signature-kaT"), crypto::kBlsTimeSignatureDst, sig));
  ASSERT_TRUE(!crypto::bls_verify(pk1, text("time-signature-kat"), crypto::kBlsTimeSignatureDst, sig));
  ASSERT_TRUE(!crypto::bls_verify(pk0, text("time-signature-kat"), crypto::kBlsPopDst, sig));
  ASSERT_TRUE(crypto::bls_pop_verify(pk0, pop));
  ASSERT_TRUE(!crypto::bls_pop_verify(pk1, pop));
  ASSERT_TRUE(!crypto::bls_pop_verify(pk0, sig));  // a time signature is not a proof of possession
  // Encodings: the identity and garbage are rejected as keys and signatures.
  crypto::BlsPublicKey inf_pk{};
  inf_pk[0] = 0xc0;  // compressed point at infinity
  crypto::BlsSignature inf_sig{};
  inf_sig[0] = 0xc0;
  ASSERT_TRUE(!crypto::bls_verify(inf_pk, text("time-signature-kat"), crypto::kBlsTimeSignatureDst, sig));
  ASSERT_TRUE(!crypto::bls_verify(pk0, text("time-signature-kat"), crypto::kBlsTimeSignatureDst, inf_sig));
  ASSERT_TRUE(!crypto::mcfly_evaluation_point(inf_pk).has_value());
  crypto::BlsPublicKey junk{};
  junk.fill(0xff);
  ASSERT_TRUE(!crypto::bls_verify(junk, text("time-signature-kat"), crypto::kBlsTimeSignatureDst, sig));
  ASSERT_TRUE(!crypto::bls_keygen(Bytes(31, 7)).has_value());  // IKM shorter than 32 bytes
  (void)sk0;
}

// The property SWE decryption relies on: for distinct non-zero points, sum_j L_j f(xi_j) = f(0)
// for every polynomial f of degree < |I|, i.e. sum L_j = 1 and sum L_j xi_j^k = 0 for 0 < k < |I|.
TEST(test_mcfly_lagrange_coefficients_interpolate_at_zero) {
  std::vector<crypto::BlsScalar> points;
  for (const auto& k : kKats) points.push_back(hex_array<32>(k.xi));
  const auto coeffs = crypto::lagrange_coefficients_at_zero(points);
  ASSERT_TRUE(coeffs.has_value() && coeffs->size() == points.size());
  crypto::BlsScalar one_b{};
  one_b.back() = 1;
  const blst_fr one = fr(one_b);
  for (std::size_t k = 0; k < points.size(); ++k) {
    blst_fr sum{};
    for (std::size_t j = 0; j < points.size(); ++j) {
      blst_fr term = fr((*coeffs)[j]);
      for (std::size_t e = 0; e < k; ++e) {
        const blst_fr x = fr(points[j]);
        blst_fr_mul(&term, &term, &x);
      }
      blst_fr_add(&sum, &sum, &term);
    }
    ASSERT_TRUE(fr_eq(sum, k == 0 ? one : blst_fr{}));
  }
  // Coefficients for {0, 2, 3} match the independent computation.
  const auto c023 = crypto::lagrange_coefficients_at_zero({points[0], points[2], points[3]});
  ASSERT_TRUE(c023.has_value());
  for (std::size_t i = 0; i < 3; ++i) ASSERT_TRUE((*c023)[i] == hex_array<32>(kLagrange023[i]));
  // Repeated or zero points have no interpolation.
  ASSERT_TRUE(!crypto::lagrange_coefficients_at_zero({points[0], points[0]}).has_value());
  ASSERT_TRUE(!crypto::lagrange_coefficients_at_zero({points[0], crypto::BlsScalar{}}).has_value());
  ASSERT_TRUE(!crypto::lagrange_coefficients_at_zero({}).has_value());
}

TEST(test_mcfly_aggregate_matches_known_answer_and_verifies) {
  std::vector<crypto::BlsPublicKey> pks;
  std::vector<crypto::BlsSignature> sigs;
  for (const auto& k : kKats) {
    pks.push_back(hex_array<48>(k.pk));
    sigs.push_back(hex_array<96>(k.sig));
  }
  const std::vector<crypto::BlsPublicKey> signers = {pks[0], pks[2], pks[3]};
  const auto agg = crypto::mcfly_aggregate(signers, {sigs[0], sigs[2], sigs[3]});
  ASSERT_TRUE(agg.has_value());
  ASSERT_TRUE(*agg == hex_array<96>(kAggregate023));
  const auto msg = text("time-signature-kat");
  ASSERT_TRUE(crypto::mcfly_aggregate_verify(signers, msg, crypto::kBlsTimeSignatureDst, *agg));
  // Every subset verifies with its own aggregate; a different signer set or message does not.
  ASSERT_TRUE(crypto::mcfly_aggregate_verify(pks, msg, crypto::kBlsTimeSignatureDst, *crypto::mcfly_aggregate(pks, sigs)));
  ASSERT_TRUE(!crypto::mcfly_aggregate_verify({pks[0], pks[1], pks[3]}, msg, crypto::kBlsTimeSignatureDst, *agg));
  ASSERT_TRUE(!crypto::mcfly_aggregate_verify(signers, text("other"), crypto::kBlsTimeSignatureDst, *agg));
  // A plain product (standard BLS aggregation) is not the McFly aggregate.
  const auto other = crypto::bls_sign(kat_secret(kKats[1]), text("other"), crypto::kBlsTimeSignatureDst);
  ASSERT_TRUE(!crypto::mcfly_aggregate_verify({pks[0], pks[1]}, msg, crypto::kBlsTimeSignatureDst,
                                              *crypto::mcfly_aggregate({pks[0], pks[1]}, {sigs[0], *other})));
  // A single signer: L = 1, the aggregate is its signature.
  ASSERT_TRUE(*crypto::mcfly_aggregate({pks[1]}, {sigs[1]}) == sigs[1]);
  ASSERT_TRUE(*crypto::mcfly_aggregate_public_key({pks[1]}) == pks[1]);
  // Shape errors.
  ASSERT_TRUE(!crypto::mcfly_aggregate({pks[0], pks[0]}, {sigs[0], sigs[0]}).has_value());
  ASSERT_TRUE(!crypto::mcfly_aggregate({pks[0]}, {}).has_value());
}
