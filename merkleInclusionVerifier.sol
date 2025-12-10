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
        vk.alpha = Pairing.G1Point(uint256(0x118fbb0a5ee9b43c18beb7635661e77ac69fd3b805e3c25f19e27686418ec89e), uint256(0x1acfa81fab5ab5e8cdf1f3790a48eb99b4863f316d0f94cc5b7a7ac57d4e8a4a));
        vk.beta = Pairing.G2Point([uint256(0x01172f2cab5971a859b185ee7c31b4c3fc3f1b63e28d6448a8949ca1cde40b22), uint256(0x02f6076c9d5bc3a99f67c7bbfcf29aa6a1dab3227569c6ac57e6eb34a10eaf44)], [uint256(0x1ee04abc4a3c10cc590e18d2fbe31fd9c2c3f4bb4f7c71fdcfbd5439ee826c28), uint256(0x1979beefaac84ae737a6a6f1dd8dab634926f16707002b45b5946d108f4178ce)]);
        vk.gamma = Pairing.G2Point([uint256(0x257c5fbf7a3ad4ceb3146571e02f987d4968db506bb29df18b9e4b40830be485), uint256(0x05e7c844dbb10d6e6d59d24a5ed575fe0b246a86714ef9e1cbe84ec956d9306f)], [uint256(0x06c46ea67cd4105a736f47ce59b9674b11332c3464eb74406a758bd159e04fea), uint256(0x0723b284133cd4379dac3041aa7fc0aa3c34bcd7c6860607a432790c58c45703)]);
        vk.delta = Pairing.G2Point([uint256(0x29c17b86d6f7b076802c259f7248f016b590aead6aeb30fb7a4e0c3385b7f80d), uint256(0x2259d0cfc24b983774b90d4bd865016331c69d752d8441ebde3f7cc3ac3b5a9e)], [uint256(0x195a91b8283b0fa4afe331642d3f3ac6ff837f722d752bf45870c9437b751ddd), uint256(0x2b9960125d06445d0d28c4ed1ad0abc528305ac55a807ce8e0544f4b1a01e99e)]);
        vk.gamma_abc = new Pairing.G1Point[](10);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2a0b8f16c28a58766e5f6755fb31a5688aea29fd79f0b4ac2e711bb13bbce2de), uint256(0x13fe7fbd27a3abffa60d80234afe1e205f4b9ed43f010c0e8153d08a4c20803b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1842fe47b77042d04a912557874d7eeaaa523218976a1add64162e339a0edbc2), uint256(0x1f4129596b15ef2fd8cfc6e8a10c281f73f3f5fdf8712310707a22a513c87baa));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1a339af39883d30074ad1c15e0a578ce2fe94e125a93f1f2bcc37484f1830b51), uint256(0x1d951a1ad956f804e9e4ff08c49d52eadf60fcc4ca744a64cce74180c32e4c92));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x234d4a5370c9716c7075d13c6c7ed7a2462929c6f5debd56407d3918abb46c1b), uint256(0x154f40dc03bc7d073a4893bde280b6931258008c3da85a85e26de403de5a0467));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0d50b9fa554211908233887d57059f4e03663ab91d09253a5f064a160bb780a0), uint256(0x202bacf9b06298f661bda3341c119129e23f9627342d5dc7282382ea208b9ea0));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x181a1c1dc9f37434d127adb0718343fb668672466aa3da04007f3fa208c067a4), uint256(0x28d633a9242f524f1abd65aa589f7c9c4ac3b33181b3d6153e172dbf9d6f0ba6));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0dc00119e28138cfb09f23e266e32e5c5611eab8f1c3fb415286a160ef17a600), uint256(0x02455136164a310fab0c27f5abc26efdf19fd32a31b772eaa26ca45f9557ce33));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x103e4ccc1c6c34ca0ed2a871abd5184b33085700894c10ec3025eb7285a8229f), uint256(0x130070488f04736beb0ec1f19fe27334cb1cde1fe1dc695983fabb7401d20dbc));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x08eca4bd6974f4e03384c0da9e38f00c05bdeb34d80f7bd7130f7ca8e7fd0462), uint256(0x14c96ff029b7a2b4dc74febd0b7fcd58dfa953e37b2f29d0320c01f5556db7bb));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x25f8e92a9990bc027a9d38ac2ac07931129ad0a0d82ebeaa322093f6172ba15b), uint256(0x0f07637580ffbfaefaee13d41c5b4c6c9f32eb8f30e1fc77f1fc86bf496d6cbb));
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
