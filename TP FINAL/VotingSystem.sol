pragma solidity ^0.8.0;

import "../library/IVerifier.sol";

struct ProofPack{
    uint256[] input;
    Proof proof;
}

contract VotingSystem {

    // Variables declaration
    ProofPack[] proofs;
    uint256 public root;
    address owner;
    uint256[2] count = 0;
    uint256 numberOfVotes = 0;
    bool electionStillOpen = true;
    
    IVerifier public verifierVotoValido;
    IVerifier public verifierResultadoCorrecto;


    // Events
    event voteEmited(uint256[2] vote, ProofPack proof, uint256 nullifier);
    event results(uint32 votes_for_candidate_0, uint32 votes_for_candidate_1, ProofPack proof);


    // Auxiliar functions
    function contains(ProofPack[] storage array, ProofPack calldata value) internal view returns (bool) {
        for (uint i = 0; i < array.length; i++) {
            if (isEqualTo(array[i], value)) {
                return true;
            }
        }
        return false;
    }

    function isEqualTo(ProofPack storage p1, ProofPack calldata p2) private view returns (bool) {
            bytes32 hash_input1 = keccak256(abi.encode(p1.input));
            bytes32 hash_input2 = keccak256(abi.encode(p2.input));
            bytes32 hash_proof1 = keccak256(abi.encode(p1.proof));
            bytes32 hash_proof2 = keccak256(abi.encode(p2.proof));
            
            return hash_input1 == hash_input2 && hash_proof1 == hash_proof2;
    }


    // Functions
    constructor(uint256 actual_root, address _address_voto_valido, address _address_resultado_correcto) {
        verifierVotoValido = IVerifier(_address_voto_valido);
        verifierResultadoCorrecto = IVerifier(_address_resultado_correcto);
        root = actual_root;
        owner = msg.sender;
    }

    // Emisión de votos
    function registerVote(uint256[2] vote, ProofPack calldata proof, uint256 nullifier) public {
        require(electionStillOpen, "Votacion finalizada");
        require(!contains(nullifiers, nullifier), "Ya fue emitido un voto con ese nullifier");
        require(verifierVotoValido.verifyTx(proof.input, proof.proof), "ZKP rechazada");

        proofs.push(proof);
        count = count + vote;
        numberOfVotes += 1;

        emit voteEmited(vote, proof);
    }

    // Termina la elección
    function terminateElection() public returns (uint256) {
        require(msg.sender == owner, "Only the owner can terminate the election.");
        electionStillOpen = false;
        return count;
    }

    // Publicación de resultados
    function publicResults(uint32 votes_for_candidate_0, uint32 votes_for_candidate_1, ProofPack calldata proof) public {
        require(msg.sender == owner, "Only the owner can post the election results.");
        require(verifierResultadoCorrecto.verifyTx(proof.input, proof.proof), "Your proof of election isn't valid.");

        emit results(votes_for_candidate_0, votes_for_candidate_1, proof);
    }

}