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

import "./libs/SignatureVerifier.sol";

contract WorkOrderRegistry is SignatureVerifier
{
	uint256 constant public TIMEOUT = 1 days;

	enum WorkOrderStatus
	{
		NULL,
		ACTIVE,
		COMPLETED,
		FAILED
	}

	struct WorkOrder
	{
		uint256 status;
		uint256 timestamp;
		bytes32 workerID;
		bytes32 requesterID;
		bytes   request;
		address verifier;
		uint256 returnCode;
		bytes   response;
	}

	// workOrderID → workOrder
	mapping(bytes32 => WorkOrder) m_workorders;

	event workOrderSubmitted(
		bytes32 indexed workOrderID,
		bytes32 indexed workerID,
		bytes32 indexed requesterID);

	event workOrderCompleted(
		bytes32 indexed workOrderID,
		uint256 indexed workOrderReturnCode);

	event workOrderTimedout(
		bytes32 indexed workOrderID);

	constructor()
	public
	{}

	function workOrderSubmit(
		bytes32       _workerID,
		bytes32       _requesterID,
		bytes memory _workOrderRequest,
		address       _verifier,
		bytes32       _salt)
	public returns (
		uint256       errorCode
	) {
		bytes32 workOrderID = keccak256(abi.encode(
			_workerID,
			_requesterID,
			_workOrderRequest,
			_verifier,
			_salt
		));

		WorkOrder storage wo = m_workorders[workOrderID];
		require(wo.status == uint256(WorkOrderStatus.NULL), "wo-already-submitted");
		wo.status      = uint256(WorkOrderStatus.ACTIVE);
		wo.timestamp   = now;
		wo.workerID    = _workerID;
		wo.requesterID = _requesterID;
		wo.request     = _workOrderRequest;
		wo.verifier    = _verifier;

		emit workOrderSubmitted(
			workOrderID,
			_workerID,
			_requesterID);

		return 0;
	}

	function workOrderComplete(
		bytes32      _workOrderID,
		uint256      _workOrderReturnCode,
		bytes memory _workOrderResponse,
		bytes memory _workOrderSignature
	) public returns (
		uint256      errorCode
	) {
		WorkOrder storage wo = m_workorders[_workOrderID];
		require(wo.status == uint256(WorkOrderStatus.ACTIVE), "wo-already-submitted");

		require(checkSignature(
			wo.verifier,
			toEthSignedMessageHash(
				keccak256(abi.encodePacked(
					_workOrderID,
					_workOrderReturnCode,
					_workOrderResponse
				))
			),
			_workOrderSignature
		));

		wo.status      = uint256(WorkOrderStatus.COMPLETED);
		wo.returnCode  = _workOrderReturnCode;
		wo.response    = _workOrderResponse;

		emit workOrderCompleted(
			_workOrderID,
			_workOrderReturnCode);

		return 0;
	}

	function workOrderTimeout(
		bytes32 _workOrderID
	) public returns (
		uint256 errorCode
	) {
		WorkOrder storage wo = m_workorders[_workOrderID];
		require(wo.status == uint256(WorkOrderStatus.ACTIVE));
		require(wo.timestamp + TIMEOUT < now);

		wo.status = uint256(WorkOrderStatus.FAILED);

		emit workOrderTimedout(_workOrderID);

		return 0;
	}

	function workOrderGet(
		bytes32      _workOrderID
	) public view returns (
		uint256      status,
		uint256      timestamp,
		bytes32      workerID,
		bytes32      requesterID,
		bytes memory request,
		address      verifier,
		uint256      returnCode,
		bytes memory response
	) {
		WorkOrder storage wo = m_workorders[_workOrderID];
		return (
			wo.status,
			wo.timestamp,
			wo.workerID,
			wo.requesterID,
			wo.request,
			wo.verifier,
			wo.returnCode,
			wo.response);
	}

}
