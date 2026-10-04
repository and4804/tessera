from ulpf.detect.source_cache import SourceCache


def test_cache_hit_miss_evict_and_bound():
    c = SourceCache(max_entries=2, evict_after=3)
    c.hit("a", "p1")
    assert c.get("a") == "p1" and c.get("zzz") is None
    c.miss("a")
    c.miss("a")
    assert c.get("a") == "p1"
    c.hit("a", "p1")          # a hit resets the consecutive-miss counter
    c.miss("a")
    c.miss("a")
    assert c.get("a") == "p1"
    c.miss("a")
    assert c.get("a") is None  # evicted after 3 consecutive misses
    c.hit("a", "p1")
    c.hit("b", "p2")
    c.hit("c", "p3")
    assert len(c) == 2 and c.get("a") is None and c.get("c") == "p3"
    c.miss("nope")
    c.clear()
    assert len(c) == 0
