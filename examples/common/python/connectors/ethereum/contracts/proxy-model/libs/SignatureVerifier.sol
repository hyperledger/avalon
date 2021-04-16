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

import "../interfaces/IERC734.sol";
import "../interfaces/IERC1271.sol";

contract SignatureVerifier
{
	function addrToKey(address _addr)
	internal pure returns (bytes32)
	{
		return bytes32(uint256(_addr));
	}

	function checkIdentity(address _identity, address _candidate, uint256 _purpose)
	internal view returns (bool valid)
	{
		return _identity == _candidate || IERC734(_identity).keyHasPurpose(addrToKey(_candidate), _purpose); // Simple address || ERC 734 identity contract
	}

	function checkSignature(
		address      _identity,
		bytes32      _hash,
		bytes memory _signature)
	internal view returns (bool)
	{
		return recoverCheck(_identity, _hash, _signature) || IERC1271(_identity).isValidSignature(_hash, _signature);
	}

	// recoverCheck does not revert if signature has invalid format
	function recoverCheck(address candidate, bytes32 hash, bytes memory sign)
	internal pure returns (bool)
	{
		bytes32 r;
		bytes32 s;
		uint8   v;
		if (sign.length != 65) return false;
		assembly
		{
			r :=         mload(add(sign, 0x20))
			s :=         mload(add(sign, 0x40))
			v := byte(0, mload(add(sign, 0x60)))
		}
		if (v < 27) v += 27;
		if (v != 27 && v != 28) return false;
		return candidate == ecrecover(hash, v, r, s);
	}

	function toEthSignedMessageHash(bytes32 msg_hash)
	internal pure returns (bytes32)
	{
		return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msg_hash));
	}

	function toEthTypedStructHash(bytes32 struct_hash, bytes32 domain_separator)
	internal pure returns (bytes32)
	{
		return keccak256(abi.encodePacked("\x19\x01", domain_separator, struct_hash));
	}
}
