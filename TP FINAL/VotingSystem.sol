// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./VerifierValidVote.sol";
import "./VerifierRecuentoValido.sol";
import "./CurveBabyJubJub.sol";

contract VotingSystem {

    // --------------------
    // State
    // --------------------

    address public owner;
    bool public electionOpen;

    uint256 public merkleRoot;

    // EC-ElGamal acumulado
    // sum(C1), sum(C2)
    CurveBabyJubJub.Point public accC1;
    CurveBabyJubJub.Point public accC2;


    uint256 public numberOfVotes;

    mapping(uint256 => bool) public nullifierUsed;

    VerifierValidVote public voteVerifier;
    VerifierRecuentoValido public recountVerifier;

    // --------------------
    // Events
    // --------------------

    event VoteRegistered(
        uint256[2] C1,
        uint256[2] C2,
        uint256 nullifier
    );

    event ElectionClosed();

    event ResultsPublished(
        uint256 result
    );

    // --------------------
    // Constructor
    // --------------------

    constructor(
        uint256 _merkleRoot,
        address _voteVerifier,
        address _recountVerifier
    ) {
        owner = msg.sender;
        electionOpen = true;

        merkleRoot = _merkleRoot;

        voteVerifier = VerifierValidVote(_voteVerifier);
        recountVerifier = VerifierRecuentoValido(_recountVerifier);

        accC1 = CurveBabyJubJub.Point(0, 1); // punto neutro Edwards
        accC2 = CurveBabyJubJub.Point(0, 1);
    }

    // --------------------
    // Vote
    // --------------------

    function registerVote(
        VerifierValidVote.Proof calldata proof,
        uint256[4] calldata publicInputs, 
        uint256[2] calldata C1,
        uint256[2] calldata C2,
        uint256 nullifier
    ) external {

        require(electionOpen, "Election closed");
        require(!nullifierUsed[nullifier], "Nullifier already used");

        // ZKP de voto válido
        bool ok = voteVerifier.verifyTx(proof, publicInputs);
        require(ok, "Invalid vote proof");

        // Marcar nullifier
        nullifierUsed[nullifier] = true;

        // Acumular cifrados (homomorfico)
        CurveBabyJubJub.Point memory pC1 = CurveBabyJubJub.Point(C1[0], C1[1]);

        CurveBabyJubJub.Point memory pC2 = CurveBabyJubJub.Point(C2[0], C2[1]);

        accC1 = CurveBabyJubJub.pointAdd(accC1, pC1);
        accC2 = CurveBabyJubJub.pointAdd(accC2, pC2);

        numberOfVotes += 1;

        emit VoteRegistered(C1, C2, nullifier);
    }

    // --------------------
    // Close election
    // --------------------

    function closeElection() external {
        require(msg.sender == owner, "Only owner");
        require(electionOpen, "Already closed");

        electionOpen = false;
        emit ElectionClosed();
    }

    // --------------------
    // Publish results
    // --------------------

    function publishResults(
        uint256 result,
        VerifierRecuentoValido.Proof calldata proof
        
    ) external {

        require(msg.sender == owner, "Only owner");
        require(!electionOpen, "Election still open");

        // Verificar que result corresponde a accC1, accC2
        uint256;
        inputs[0] = accC1.x;
        inputs[1] = accC1.y;
        inputs[2] = accC2.x;
        inputs[3] = accC2.y;
        inputs[4] = result;
        bool ok = recountVerifier.verifyTx(proof, publicInputs);
        require(ok, "Invalid recount proof");

        emit ResultsPublished(result);
    }
}
