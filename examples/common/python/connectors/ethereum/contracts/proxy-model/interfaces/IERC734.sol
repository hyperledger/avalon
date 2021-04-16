/* Copyright 2019 iExec Blockchain Tech
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at 
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

pragma solidity ^0.5.0;

contract IERC734
{
	// 1: MANAGEMENT keys, which can manage the identity
	uint256 public constant MANAGEMENT_KEY = 1;
	// 2: ACTION keys, which perform actions in this identities name (signing, logins, transactions, etc.)
	uint256 public constant ACTION_KEY = 2;
	// 3: CLAIM signer keys, used to sign claims on other identities which need to be revokable.
	uint256 public constant CLAIM_SIGNER_KEY = 3;
	// 4: ENCRYPTION keys, used to encrypt data e.g. hold in claims.
	uint256 public constant ENCRYPTION_KEY = 4;

	// KeyType
	uint256 public constant ECDSA_TYPE = 1;
	// https://medium.com/@alexberegszaszi/lets-bring-the-70s-to-ethereum-48daa16a4b51
	uint256 public constant RSA_TYPE = 2;

	// Events
	event KeyAdded          (bytes32 indexed key, uint256 indexed purpose, uint256 indexed keyType);
	event KeyRemoved        (bytes32 indexed key, uint256 indexed purpose, uint256 indexed keyType);
	event ExecutionRequested(uint256 indexed executionId, address indexed to, uint256 indexed value, bytes data);
	event Executed          (uint256 indexed executionId, address indexed to, uint256 indexed value, bytes data);
	event ExecutionFailed   (uint256 indexed executionId, address indexed to, uint256 indexed value, bytes data);
	event Approved          (uint256 indexed executionId, bool approved);

	// Functions
	function getKey          (bytes32 _key                                     ) external view returns (uint256[] memory purposes, uint256 keyType, bytes32 key);
	function keyHasPurpose   (bytes32 _key, uint256 purpose                    ) external view returns (bool exists);
	function getKeysByPurpose(uint256 _purpose                                 ) external view returns (bytes32[] memory keys);
	function addKey          (bytes32 _key, uint256 _purpose, uint256 _keyType ) external      returns (bool success);
	function removeKey       (bytes32 _key, uint256 _purpose                   ) external      returns (bool success);
	function execute         (address _to, uint256 _value, bytes calldata _data) external      returns (uint256 executionId);
	function approve         (uint256 _id, bool _approve                       ) external      returns (bool success);
}
