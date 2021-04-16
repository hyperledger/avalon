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

library Set
{
	struct set
	{
		bytes32[] members;
		mapping(bytes32 => uint256) indexes;
	}

	function length(set storage _list)
	internal view returns (uint256)
	{
		return _list.members.length;
	}

	function at(set storage _list, uint256 _index)
	internal view returns (bytes32)
	{
		return _list.members[_index - 1];
	}

	function indexOf(set storage _list, bytes32 _value)
	internal view returns (uint256)
	{
		return _list.indexes[_value];
	}

	function contains(set storage _list, bytes32 _value)
	internal view returns (bool)
	{
		return indexOf(_list, _value) != 0;
	}

	function content(set storage _list)
	internal view returns (bytes32[] memory)
	{
		return _list.members;
	}

	function add(set storage _list, bytes32 _value)
	internal returns (bool)
	{
		if (contains(_list, _value))
		{
			return false;
		}
		_list.indexes[_value] = _list.members.push(_value);
		return true;
	}

	function remove(set storage _list, bytes32 _value)
	internal returns (bool)
	{
		if (!contains(_list, _value))
		{
			return false;
		}

		uint256 i    = indexOf(_list, _value);
		uint256 last = length(_list);

		if (i != last)
		{
			bytes32 swapValue = _list.members[last - 1];
			_list.members[i - 1] = swapValue;
			_list.indexes[swapValue] = i;
		}

		delete _list.indexes[_value];
		--_list.members.length;

		return true;
	}

}
