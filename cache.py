from collections import OrderedDict
from typing import Optional, Tuple

from cryptree import CryptTreeNode

class LRUCache:
    def __init__(self, capacity: int):
        self.cache = OrderedDict()
        self.capacity = capacity

    def contains_key(self, key) -> bool:
        return key in self.cache

    def get(self, key) -> Optional[CryptTreeNode]:
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        return None

    def put(self, key, value) -> None:
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)

class CryptreeCache:
    def __init__(self):
        cache_size = 1000
        self.cache = LRUCache(cache_size)

    def contains_key(self, cache_key: Tuple) -> bool:
        return self.cache.contains_key(cache_key)

    def get(self, cache_key: str) -> Optional[CryptTreeNode]:
        return self.cache.get(cache_key)

    def put(self, cache_key: str, val: CryptTreeNode) -> None:
        self.cache.put(cache_key, val)

    def update(self, prior_root: CryptTreeNode, cache_key: Tuple, val: CryptTreeNode) -> None:
        if prior_root is not None:
            temp_dict = dict(self.cache.cache)
            for key, value in temp_dict.items():
                if key[0] == prior_root:
                    self.cache.put((cache_key[0], key[1]), value)
        self.cache.put(cache_key, val)


## Unit Test 
import unittest
from collections import namedtuple

class TestLRUCache(unittest.TestCase):

    def setUp(self):
        self.cache = LRUCache(3)

    def test_contains_key(self):
        self.cache.put("test", "value")
        self.assertTrue(self.cache.contains_key("test"))
        self.assertFalse(self.cache.contains_key("missing"))

    def test_get(self):
        self.cache.put("test", "value")
        self.assertEqual(self.cache.get("test"), "value")
        self.assertIsNone(self.cache.get("missing"))

    def test_put_with_eviction(self):
        self.cache.put("a", 1)
        self.cache.put("b", 2)
        self.cache.put("c", 3)
        self.cache.put("d", 4)
        self.assertFalse(self.cache.contains_key("a"))
        self.assertTrue(self.cache.contains_key("d"))

    def test_lru_ordering(self):
        self.cache.put("a", 1)
        self.cache.put("b", 2)
        self.cache.get("a")  # Access "a" to move it to the end.
        self.cache.put("c", 3)
        self.cache.put("d", 4)
        self.assertFalse(self.cache.contains_key("b"))
        self.assertTrue(self.cache.contains_key("a"))


if __name__ == "__main__":
    unittest.main()
