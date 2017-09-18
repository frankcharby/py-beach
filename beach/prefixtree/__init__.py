# Copyright 2012 Aaron Iles
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Trie based implemenation of dict and set.

Provides two collection classes:

* PrefixDict, a dictionary like object
* PrefixSet, a set like object

"""
from beach.prefixtree.version import __version__
from beach.prefixtree.collections import PrefixDict
from beach.prefixtree.collections import PrefixSet

__all__ = ['PrefixDict', 'PrefixSet']
