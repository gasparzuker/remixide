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
        vk.alpha = Pairing.G1Point(uint256(0x133b63c23140beab6d51521f300a581c0af7f9241f67d94cb3918615ea0371bb), uint256(0x18f935f89fb1d50b2daa887332a1c47f7469dc5ac785b5b9ed08b524b3011036));
        vk.beta = Pairing.G2Point([uint256(0x0d1a77bfd198416571f35dbc53ea3afb6c68b9b8889b424f393106f79f021907), uint256(0x1565ce90a9f43395cd11a70425c1e743830629ec63f9e00ab2cb9b6c2b0b0153)], [uint256(0x2385fe80197ceda66a19516e59d72a22458be4e7d73d52140bac30699d0e9971), uint256(0x2152d52138b42d690a3a17191b0fb509aedfebb61616cb2628dfbbe649984075)]);
        vk.gamma = Pairing.G2Point([uint256(0x18edb35a900af22643cd3971c795a7850314bc767df5b9ff0c4ee176d1f35188), uint256(0x065a01945191f43c475169382a5f9d24cc66ec2fa83aa703b6fcf2383a905861)], [uint256(0x057024dd30f1d5113c090d1ed54f47a5827c0a025051aedd47067d4b039ad581), uint256(0x01a938ac51c16b28e7ec0e452e79e608160f65ac6a48cea350547df7096cbb19)]);
        vk.delta = Pairing.G2Point([uint256(0x0435de569fde328e429f5c7ecf2fb2174a2bf3ac5c0b2b1b6bd785e07d7bfbc3), uint256(0x15672ffc7be8c35aa45624f2698161e3e42bf1d3d093c71341f392dd4620c7d4)], [uint256(0x1dd24d405761803d9e86e2d8deb360f5b9451b83df938dcf851bfa75213471bf), uint256(0x1962aeb2cee1082c0e372b9c8f98b057012f8527f9fe73cbc0405efc305e3603)]);
        vk.gamma_abc = new Pairing.G1Point[](10);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1b95f5bd07ee2762381f0a46a47032d2b9dc8e6fdee7c3a19160265c7ee85589), uint256(0x13c7f17867b14b319fed779202d2988fd4e9feb2f3c901cfa284af04171de83c));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1073a38ff84d2091054c0c39c55643629400af355b5f64cd6c449352d05414a2), uint256(0x123ed701168355b936661cdec67976de5679184243bfc3d8cef7f7437e3f49ce));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1e55fefba27cbfac3973785b1afd11bc619780c88e1e6a58d578da411dd670e8), uint256(0x19478e5cee611a9878aed3e202a94b9b4b8f0960eb8e8b26c0a0592953137762));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2568b8929ed8c2ee71b9137de703c77dc2223c21c75d7e19d4bdf7375823ba4b), uint256(0x1158cfe02fd08fd3ad904c4cfa5a1c6184d4019a77552ea30db2f9b8c70faec1));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2d1d90245fb5af82edfda536cef69408945579c02fd4687f0ee7c6a3ae98ac18), uint256(0x0f6a993a53f53d9756b228e8d7ca4f3f15035fa94321928c7916f41a932be8c7));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x02339029c0073ab848d940f0b379ae058f7a955359ddb9f4b61d924d2995a373), uint256(0x115bca8c8a7d4487eedf2b19485f7d09668170a5c5e5e3e5cc626f9941e8df75));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0ba4bdf7a2d8ba8ca844eeb71a3acb98aa002a924bccfac2648a8987adb4bd6f), uint256(0x0d5671446e66de0b99468ec2776547bb0c5c1dd93040911bd6babe2384f0cce0));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0baf0dac40ff19dc56f656f6c38bc7979f5811b7e132eee7f8436299485246b7), uint256(0x18e630f323ebdf6de4c5f546b670bb7df9b12c07c0bb804f854606c4d1d4b53c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x29b7a9cfb13e3120e906c1b540a1d8c22915e1ae2fdacd86e565a8212f90ea34), uint256(0x291d7048946fcea7f25c8d51593fcde0db8b2a19675303cbacf37d4e0f1267bc));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x23858853d30778a16dce84b2e170232dd349c3710387262ffa87a0cd02542b6b), uint256(0x1fc2d1680ead8ae6ad0a971d6a996215e0de0fce000ae7c28b689ce0002a0335));
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
            Proof memory proof, uint[9] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](9);
        
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
