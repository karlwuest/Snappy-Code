pragma solidity ^0.4.24;

import "./Pairing.sol";
import "./BLS.sol";
import "./BN256G2.sol";

contract Snappy {
     
     struct Transaction {
         address merchant;
         uint256 value;
         bool exists;
         uint256 signature_x;
         uint256 signature_y;
         uint256 signers; // bitmap to indicate signers, currently limits to 256 Statekeepers
         bool temp_mark;
         bool verified;
     }
     
     struct Client {
         bool exists; // to check whether an address is a client
         uint256 collateral; // total collateral
         uint256 released; // block number at which release of collateral was requested
         uint256 max_cnonce; // maximum nonce seen for client
         uint256 cnonce_counter; // counter of cnonces to efficiently check that all cnonces exist for settlement 
         mapping (uint256 => Transaction) transactions; // maps cnonce to transaction
     }
     
     struct Statekeeper {
         bool exists; // to check whether an address is a Statekeeper
         uint256 collateral; // total collateral
         uint256 remaining_collateral; // collateral that is remaining
         uint256 released;   // block number at which release of collateral was requested
         Pairing.G2Point BLSkey;
         mapping (address => uint256) claimed; // mapping from merchant to allocated collateral per merchant, currently not used
     }
     
     uint256 eon;
     uint256 max_pending = 3;
     mapping (address => Client) clients;
     mapping (address => Statekeeper) statekeepermap;
     address[] statekeepers;
     
     mapping (address => bool) merchantmap;
     address[] merchants;
     
     // dirty... local variable limit
     uint256 existing_cnonces;
     uint256 tot_pending;
     
     constructor(uint256 _eon) public {
         eon = _eon;
     }
     
     function registerMerchant() public {
         require(!merchantmap[msg.sender]);
         merchants.push(msg.sender);
         merchantmap[msg.sender] = true;
     }
     
     function registerClient() public payable {
         require(!clients[msg.sender].exists);
         // should probably require minimum collateral in practice
         clients[msg.sender].collateral = msg.value;
         clients[msg.sender].exists = true;
     }
     
     function registerStatekeeper(uint256[2] key_x, uint256[2] key_y, uint256 signature_x, uint256 signature_y) public payable {
         require(!statekeepermap[msg.sender].exists);
         // should probably require minimum collateral in practice
        Pairing.G1Point memory signature = Pairing.G1Point({
            x: signature_x,
            y: signature_y
        });
        Pairing.G2Point memory BLSkey = Pairing.G2Point({
            x: key_x,
            y: key_y
        });
        
        // check that statkeeper signed his own key (to prevent rogue key attacks)
        require(BLS.verify(BLSkey, abi.encodePacked(key_x, key_y), signature));
        statekeepermap[msg.sender].BLSkey = BLSkey;
        statekeepermap[msg.sender].collateral = msg.value;
        statekeepermap[msg.sender].remaining_collateral = msg.value;
        statekeepermap[msg.sender].exists = true;
        statekeepers.push(msg.sender);
     }
     
     function requestClientRelease() public {
         require(clients[msg.sender].exists);
         clients[msg.sender].released = block.number;
     }
     
     function requestStatekeeperRelease() public {
         require(statekeepermap[msg.sender].exists);
         statekeepermap[msg.sender].released = block.number;
     }
     
     // could be split up into two functions, currently withdraws everything possible, if adress is both client and statekeeper
     function withdraw() public {
         uint256 collateral = 0;
         uint256 released = clients[msg.sender].released;
         if (released != 0 && released + eon <= block.number) {
             collateral += clients[msg.sender].collateral;
             clients[msg.sender].collateral = 0;
             clients[msg.sender].exists = false;
             clients[msg.sender].released = 0;
         }
         released = statekeepermap[msg.sender].released;
         if (released != 0 && released + eon <= block.number) {
             collateral += statekeepermap[msg.sender].collateral;
             statekeepermap[msg.sender].collateral = 0;
             statekeepermap[msg.sender].exists = false;
             statekeepermap[msg.sender].released = 0;
         }
         msg.sender.transfer(collateral);
     }
     
 
    // perform payment
    function processPay(address merchant, 
                        uint256 cnonce, uint256 signature_x, uint256 signature_y, uint256 sk_signers) public payable {
        require(clients[msg.sender].exists);
        // check if transaction was already executed 
        require(!clients[msg.sender].transactions[cnonce].exists);
        clients[msg.sender].max_cnonce = cnonce;
        clients[msg.sender].cnonce_counter += 1;
        clients[msg.sender].transactions[cnonce].exists = true;
        clients[msg.sender].transactions[cnonce].merchant = merchant;
        clients[msg.sender].transactions[cnonce].value = msg.value;
        clients[msg.sender].transactions[cnonce].signature_x = signature_x;
        clients[msg.sender].transactions[cnonce].signature_y = signature_y;
        clients[msg.sender].transactions[cnonce].signers = sk_signers;
        merchant.transfer(msg.value);
    } 
    
    /*
    each array contains the coresponding fields from the disputed transaction or a pending transaction
    transaction with index 0 is the disputed transaction
    */
    function claimCust(address _client, uint256[] clientSig, uint256[] value, address[] merchant, 
                        uint256[] cnonce, uint256[] signature_x, uint256[] signature_y, uint256[] sk_signers) internal returns (uint256 overexposure) {
        Client storage client = clients[_client];
        // client has to exists
        require(client.exists);
        // at most 'max_pending' pending transactions
        require(cnonce.length <= max_pending);
        // lengths have to match
        require(clientSig.length == 3*cnonce.length && value.length == cnonce.length 
            && merchant.length == cnonce.length && signature_x.length == cnonce.length 
            && signature_y.length == cnonce.length && sk_signers.length == cnonce.length);
            
        uint256 i;
        tot_pending = 0;
        bytes memory data;
        
        // adjust the number of seen cnonces to disregard larger cnonces than the current tx
        existing_cnonces = client.cnonce_counter;
        if (client.max_cnonce > existing_cnonces) {
            for (i = client.max_cnonce; i > cnonce[0]; i--) {
                if (client.transactions[i].exists) {
                    existing_cnonces--;
                }
            }
        }
        
        // check that pending transactions don't have duplicates and calculate pending transaction value
        for (i = 1; i < cnonce.length; i++) {
            require(cnonce[i] < cnonce[0] && cnonce[i] > cnonce[0] - max_pending);
            require(!client.transactions[i].temp_mark);
            client.transactions[i].temp_mark = true; // mark to make sure pending transactions don't contain duplicates
            // calculate total value
            tot_pending += value[i];
            // adjust number of seen cnonces
            if (!client.transactions[cnonce[i]].exists) {
                existing_cnonces++;
            }
        }

        // remove temp_mark
        for (i = cnonce[0] - max_pending; i < cnonce[0]; i++) {
            client.transactions[i].temp_mark = false;
        }
        
        // check that all cnonces up to cnonce[0] have been seen
        require(existing_cnonces == cnonce[0]);
        
        // check validity of all pending transactions, abort if invalid
        for(i = 0; i < cnonce.length; i++) {
            // Use commitments over necessary fields
            data = abi.encodePacked(address(this), "SnappyPayment", _client, value[i], merchant[i], cnonce[i]);
            // currently hashing data before including in this hash, otherwise length in prefix has to be adjusted dynamically, which is complicated in solidity
            // check client signature
            require(_client == ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(data))),uint8(clientSig[i*3])+27,bytes32(clientSig[i*3+1]),bytes32(clientSig[i*3+2])));
            // check BLS signature
            require(verifyAggregateSig(sk_signers[i], data, signature_x[i], signature_y[i]));
        }
        
        // if transaction with same cnonce already exists, check signature, if valid return, otherwise continue
        if (client.transactions[cnonce[0]].exists) {
            data = abi.encodePacked(address(this), "SnappyPayment", _client, 
                    client.transactions[cnonce[0]].value, client.transactions[cnonce[0]].merchant, cnonce[0]);
            if (client.transactions[cnonce[0]].verified) {
                client.transactions[cnonce[0]].verified = true;
                return;
            } else {
                if (verifyAggregateSig(client.transactions[cnonce[0]].signers, data, 
                    client.transactions[cnonce[0]].signature_x, client.transactions[cnonce[0]].signature_y)) {
                    client.transactions[cnonce[0]].verified = true;
                    return;
                }
            }
        }
        
        client.transactions[cnonce[0]].exists = true;
        client.transactions[cnonce[0]].merchant = merchant[0];
        client.transactions[cnonce[0]].value = value[0];
        client.transactions[cnonce[0]].signature_x = signature_x[0];
        client.transactions[cnonce[0]].signature_y = signature_y[0];
        client.transactions[cnonce[0]].signers = sk_signers[0];
        client.transactions[cnonce[0]].verified = true;
        
        // check overexposure
        if (client.collateral >= tot_pending) {
            client.collateral -= value[0];
            overexposure = 0;
        } else {
            overexposure = tot_pending - client.collateral;
            client.collateral -= (value[0] - overexposure);
        }
        
        // transfer money covered by the client collateral
        merchant[0].transfer(value[0] - overexposure);
    } 
    
    // This should only get called after ClaimCust
    function claimSK(uint256 overexposure, address client, uint256[] value, address[] merchant, 
                        uint256[] cnonce, uint256[] sk_signers) internal {
        uint256 left = overexposure;
        for (uint256 i=0; i<cnonce.length && left > 0; i++){
            Transaction storage txn = clients[client].transactions[cnonce[i]];
            if (txn.exists && (txn.merchant != merchant[i] || txn.value != value[i])) {
                if (txn.verified || verifyAggregateSig(txn.signers, abi.encodePacked(address(this), "SnappyPayment", client, txn.value, txn.merchant, cnonce[i]), txn.signature_x, txn.signature_y)) {
                    // at least one statekeeper equivocated
                    txn.verified = true;
                    // find overlap of statekeepers per transaction
                    address[] memory overlap = findOverlap(txn.signers, sk_signers[i]);
                    for (uint256 j = 0; j< overlap.length  && left > 0; j++) {
                        // check how much of the equivocating statekeepers collateral can be claimed by the merchant
                        uint256 claimable = (statekeepermap[overlap[j]].collateral/merchants.length) - statekeepermap[overlap[j]].claimed[merchant[0]];
                        if (claimable > statekeepermap[overlap[j]].remaining_collateral) {
                            claimable = statekeepermap[overlap[j]].remaining_collateral;
                        }
                        if (claimable > left) {
                            statekeepermap[overlap[j]].remaining_collateral -= left;
                            statekeepermap[overlap[j]].claimed[merchant[0]] += left;
                            left = 0;
                        } else {
                            statekeepermap[overlap[j]].remaining_collateral -= claimable;
                            statekeepermap[overlap[j]].claimed[merchant[0]] += claimable;
                            left -= claimable;
                        }
                    }
                }
            }
        }
        // send the value covered by statekeeper collateral (overexposure - left) to merchant
        merchant[0].transfer(overexposure - left);
    } 
    
    function findOverlap(uint256 signers_a, uint256 signers_b) view internal returns (address[] sk) {
        uint256 overlap = signers_a & signers_b;
        uint256 mask = 1;
        uint256 i;
        uint256 j = 0;
        uint256 n_overlap = 0;
        if (overlap != 0) {
            // need to do 2 loops due to limitations of evm, first need to know how large the response should be
            for (i = 0; i <256; i++) {
                if ((mask & overlap) != 0) {
                    n_overlap += 1;
                }
                mask *= 2;
            }
            mask = 1;
            sk = new address[](n_overlap);
            for (i = 0; i <256; i++) {
                if ((mask & overlap) != 0) {
                    sk[j] = statekeepers[i];
                    j++;
                }
                mask *= 2;
            }
        }
    }
    
    function settlement(address client, uint256[] clientSig, uint256[] value, address[] merchant, 
                        uint256[] cnonce, uint256[] signature_x, uint256[] signature_y, uint256[] sk_signers) public {
        uint256 overexposure = claimCust(client, clientSig, value, merchant, cnonce, signature_x, signature_y, sk_signers);
        if (overexposure > 0) {
            claimSK(overexposure, client, value, merchant, cnonce, sk_signers);
        }
    }
    
    function verifyAggregateSig(uint256 _signers, bytes message, uint256 signature_x, uint256 signature_y) internal returns (bool) {
        // aggregate key
        address [] memory signers = findOverlap(_signers, _signers);
        if (signers.length < statekeepers.length/2 + 1) {
            return false;
        }
        uint256[] memory key_x1 = new uint256[](signers.length);
        uint256[] memory key_x2 = new uint256[](signers.length);
        uint256[] memory key_y1 = new uint256[](signers.length);
        uint256[] memory key_y2 = new uint256[](signers.length);
        for (uint256 i = 0; i < signers.length; i++) {
            key_x1[i] = statekeepermap[statekeepers[i]].BLSkey.x[0];
            key_x2[i] = statekeepermap[statekeepers[i]].BLSkey.x[1];
            key_y1[i] = statekeepermap[statekeepers[i]].BLSkey.y[0];
            key_y2[i] = statekeepermap[statekeepers[i]].BLSkey.y[1];
        }
        
        Pairing.G2Point memory aggregateKey;
        (aggregateKey.x[0], aggregateKey.x[1], aggregateKey.y[0], aggregateKey.y[1]) = BN256G2.ECTwistSum(key_x1, key_x2, key_y1, key_y2);
        
        Pairing.G1Point memory signature = Pairing.G1Point({
            x: signature_x,
            y: signature_y
        });
        
        return BLS.verify(aggregateKey, message, signature);
    }
}

