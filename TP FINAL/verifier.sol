// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x0f74b74b52eb5b78f145d13313e3ddb87b37437ec8d7ef296a2422e6663f919c), uint256(0x2a8ac117f876b0890db2ed9b850b0a8c35f075cacff4928d22169d37fd6f55b7));
        vk.beta = Pairing.G2Point([uint256(0x1ee86a41be2e25a904051ed180851af8db674df9bd1195c29cf5efb77138e62d), uint256(0x20362661ac11b8e07f2525c17309243eb2995312018ca03f76f7181191da2439)], [uint256(0x0ab5ca00d6af197aed9b36e2f8ef33e841ced413b01cdda929df721a437fb2d8), uint256(0x0c70abae26899954c3a9435a8d25432609da3e462f4b19176ee8b61620dca312)]);
        vk.gamma = Pairing.G2Point([uint256(0x1f82ba1eaa9445982c5dda0dd97c56730d8312c40b34d7937c330cc5da862367), uint256(0x1bf480076d664a3011a9df8472616d55b01e24802e5a7177ff9dd09917cd12d8)], [uint256(0x2d9883f363428067b05838ccef763b41270b262cb3161a9aad0ab100fa4a88f3), uint256(0x2ebb08c56eb2a26dadcd361e474ba78c650cff1d8a0d38d58f66b3232096294b)]);
        vk.delta = Pairing.G2Point([uint256(0x0d02f689e0550c473a0dfea1fa2cfbd523197a6b42f46d85b6bceeff218042dd), uint256(0x2587aa3a1c5a0208a4c9b8c175551f1e5e00104365e9a55347d46ea2ed22a5ff)], [uint256(0x0f845453fae09da426233d82851170b3fe6ae9818050c9fc64504150b0507060), uint256(0x09c5507004cbdda6bfa31e87b24ca21023d6a3a10225b6e854c76bc88efda194)]);
        vk.gamma_abc = new Pairing.G1Point[](13);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x181b991655f34c8a0910b4629bb3010eef46890ad14ff274a5dda50346140517), uint256(0x064bb49bf09ca5827e1fde9a62e27baf38cad7bc6b6299d49c5bf8623ecd1577));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x08e650b190dd7fb07ad34b81fbc7c1e7ca95bf912a24fc23d4523decd795f4e1), uint256(0x2fb04ebe491fdab3fad438dfeca6aef71572c768d9a0adf1784bd14d8dfb575d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x20d0b8ed432c904a7f3bf7f9074cfd632ccce8c0a3b1e5322df313030cd74bc3), uint256(0x1d9935d46b87ba91c4f0835579b2571220f189899332d122c91723548d7e2ab1));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x269b10913a4b72b8c9071808587f538020a2e9889a050f686ce63bdf5d4f4926), uint256(0x2ffe855b62f37687d3938bec4a53ff39afc6af3baabe613441ed2776ce35e983));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x26fcdb1163fa33691474f6e602aefb95084188112cd87e88b438661b65a6eddb), uint256(0x035e21054844a7377afbc045e985157680756378ef761d8e9333da4499d46b6e));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x11cf4a76228ac6eb57641c54301fe3813f6dd4e5b53d2425a58ae5e681d4aa73), uint256(0x08ebc3211417ca7205154ae97cbd74e10eb2cb8a4d21d9d6919af39cb09b3a45));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x030c13b7a4938febeda2eec713ded1ab2e0159ef1ab370644e0b5ebb37b84e98), uint256(0x233798a9979de7ec7d77de7de1b69527469437e05c03d6b9152cf8b083d6f035));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x11a4af8382fa313d85a4d3201b978b72ff7c12ff580e6dcdd8eb1c665ceb03f8), uint256(0x1e184e65651591a6798ba036eb3397976f72a9c11c2e64346f30a0c8b9f94b34));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x119f85830556cc4e976b8827743257dbae649ff6fa3c3b48730f168606aa7e81), uint256(0x03807f265c0be0420c5a17ec1e2795fe83e3c3b48af976c18fe5262f10124782));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x07384dd3021a06c0ced972fa91115f5a833a23083aa4cdc49b40317861966453), uint256(0x17f529945300e2f7e82d6003f879d241c167d1419765d4d1d83d114a1aec53d1));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2ca717493b505b22e20bd746d77e0ea6db98dc5febdcff26a9c7f0a6cbbc2a7e), uint256(0x2b2e25bef73edc666f09e904d0148589bcff56ffba75c6a01e5268802d4fd9b4));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1b0a0075ec8a0f202a874e107ca888429c6aa5e94f80b32a82aa1ab50a2ce654), uint256(0x0621418e3ec1f77bff37c67c0007633eed1f953d88f3e7fca2466226f6d15790));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x27b2e2bb0c89a909b9e47d3a5f292c12ab459cafb215869449eb83738d83c1bc), uint256(0x15b848506766cf750a76966e7d2599a090668479b7bdc371fac60bc346bb6fe8));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[12] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](12);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
