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
        vk.alpha = Pairing.G1Point(uint256(0x28a7729804d9784737152ba161e9b5bb3075adf4dbe2fb7bca382216cddd6d70), uint256(0x28784a9669ed9a0a339d22b73f39b4ff0eb15f5ce1b7426ce6cba26b39772317));
        vk.beta = Pairing.G2Point([uint256(0x0e6e11738f4757f3df0986e0122743121956c43471b337241e1a130c722858ec), uint256(0x2d65d4fe199b98e9182ccb71d3877da10fdd277e6111ef0b709c6cfaa8840308)], [uint256(0x22f7daee6dd380548926f390b2e5ccbd52c2e9ff6e64ad903f12ff872876a37d), uint256(0x0a121cf0cf08910ed781228eb30edc6528fcb63ef2d624859b8311a1fd94d43c)]);
        vk.gamma = Pairing.G2Point([uint256(0x269f66b3ce49dab8bf3eeaf1b8815c5347fe986bc68b44bf9738780744e5ccdb), uint256(0x2fd45e1eb6617859a5d7f3fa555b40d86c4154e6a2cf0034bd3222fff296b3ca)], [uint256(0x04f94bd8573dbcf47ee1313af6ad79ffcaf21ad60f4bb4ccdebe43f3369c5dee), uint256(0x1c1d5b5ceb346ec69040a6d6c687960bcba9adbb3b626d2043450e9e12dbf6a2)]);
        vk.delta = Pairing.G2Point([uint256(0x20b716b6c087263484e0665da2edd5448a3afc07ed399598ab9d4fe51d4673c2), uint256(0x2be69cabfcd1ca824594d678eafb7606a63d4ac8c88b54359db9cb9efdb5b009)], [uint256(0x2d6251b9b12e346d39b87256520a546bf9b76135c815bc5f06b083e396e9ab84), uint256(0x01ec3a52a96658f2a1cfbf70aad62515fb27c25b29240a4b5b8b7e99ffa53769)]);
        vk.gamma_abc = new Pairing.G1Point[](13);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1deef4c2163c27ef391a67129bff86ac96fd4f255f20f0387bf8382c99241488), uint256(0x25d8aebada2fe633dddff87d3a2f3fde80e559a0a2c5f96be63bfd7c83604402));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0ce914d7009ed6549895785755e62171d10b0dc88f90cd2c3545116d2da3868e), uint256(0x094c15f9a4a4a981aa152456f33b467b56c183ba0b9ce2e4fc6b5a1b35d45924));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2176329002eaca982d0fafffd371b95553b7ba6b595caa5952d2031677905e14), uint256(0x0276de88554a48c91efb6116208bb83a49fd4c04a69d3022f426248eb46095ad));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x04fdde8cbf46445df350925504ba0ba0dfb069aca2c0a9e52b60994a22265a70), uint256(0x110040cd9d9b9cc7f5beee07b1fd78deb4c942ada14836a2a371a7a7086b775d));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1de361fad29615559888fd87f7e26896acb358d92e7652e027bcb51efdcc3817), uint256(0x1592e6746475ad488afcff1b19d3bb60e900a75a5a00311e515814a3acab99ac));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0b486bc7267410a315d45a2033e80c24afd73b92e308db08835be523ecac9e27), uint256(0x1fe232523b83eccd37db23b3ea381e992168b4087838421e0afb703ecd634c2a));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2b01058f10c05d33184e3d146e134f5c24a3ba9dca0b7a9e8e4df49a6c284927), uint256(0x189d5092a7cec07849e3fc6f40970bb7c778590d17670c17d79c013092c4134b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x01eafab0be54246f0612615f7c4926e524643094ceec5e2d1e408a2ca83d027b), uint256(0x10ce98a135cd3b80e8c9fbd205e354ca3d526878ecfbe2803892842a187f78a5));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0c65ce40152eba575a15253dd929f5074bdb3746811a8e13f1fd4b41bf0284fc), uint256(0x0e1f3ed6ea56b4b51148b6b8735eb31595c63fbd414facb84a84f6a122aeba15));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2a71a8b23d9e78b23664642644148d2caeee718b445bfcc028ee6876cb55ed2c), uint256(0x0b9ddaf66f5f4cac359d07ecf7cfdb3caf40627a7673f5e1c2de77f2f25df31b));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2134ae21d4b4a30f4462f471df99d59e476f3d1b5004533624639cde55ddea1f), uint256(0x018071500c6ab3c5cafafd511958d76e1deee4c8700397991758d1829311f7e0));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x02d23e166e9fad75b3e4d328e1bf2f35372dce751550ed21a10ec4b96491b4c1), uint256(0x0361bc0450dde385c9c8301f6e73995e5190f44f903d9fc6474ec16fb0995b7e));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1d51d31d0477236fc08266d0205de543fcfa65443c4f2bd453fbbcfee8279ab5), uint256(0x2a1b55cf51f4f2b414a710eab948346ade0b7e85c80536ed61fc878c326e6e6c));
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
