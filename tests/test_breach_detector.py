from rbcollector.breach_detector import (
    BreachDetector,
    find_pivot_targets,
    ingest_out_file,
)


class FakeStore:
    def __init__(self):
        self.recorded = []

    def record_possible_breach(self, *, seat, target_host):
        key = (seat, target_host)
        is_new = key not in self.recorded
        if is_new:
            self.recorded.append(key)
        return is_new


def _session(container="red-01"):
    return f'Script started on 2026-08-19 01:44:57+00:00 [COMMAND="docker exec -it {container} bash" TERM="xterm-256color" TTY="/dev/pts/3"]\n'


def _title(host, user="root"):
    return f"\x1b]0;{user}@{host}: /\x07"


def test_find_pivot_targets_no_change_is_not_a_pivot():
    # 同一個 session 裡 host 從頭到尾都一樣——正常情況，不該有任何 pivot。
    content = _session() + _title("abc123") + _title("abc123") + _title("abc123")
    assert find_pivot_targets(content) == []


def test_find_pivot_targets_container_recreate_across_sessions_is_not_a_pivot():
    # 真實觀察到的情況：席位容器被 Metis 重建，兩次 session 之間 hostname
    # 換了，但都各自緊接在自己的 "Script started on" 之後——不是 pivot。
    content = (
        _session() + _title("hostA") + _title("hostA")
        + _session() + _title("hostB") + _title("hostB")
    )
    assert find_pivot_targets(content) == []


def test_find_pivot_targets_mid_session_host_change_is_a_pivot():
    # 同一個 session 內，host 從 red-01 自己的容器換成別的——這才是真的
    # pivot 信號。
    content = _session() + _title("red-01-host") + _title("red-01-host") + _title("dc-01")
    assert find_pivot_targets(content) == ["dc-01"]


def test_find_pivot_targets_dedupes_repeated_pivot_target():
    content = _session() + _title("baseline") + _title("dc-01") + _title("dc-01") + _title("dc-01")
    assert find_pivot_targets(content) == ["dc-01"]


def test_find_pivot_targets_multiple_distinct_pivots_in_order():
    content = _session() + _title("baseline") + _title("dc-01") + _title("web-02") + _title("dc-01")
    assert find_pivot_targets(content) == ["dc-01", "web-02"]


def test_find_pivot_targets_no_session_marker_uses_first_title_as_baseline():
    # 沒有 "Script started on" 這行也不該壞掉（例如檔案被截斷）——退回用
    # 第一個看到的 host 當基準。
    content = _title("baseline") + _title("baseline") + _title("dc-01")
    assert find_pivot_targets(content) == ["dc-01"]


def test_ingest_out_file_records_pivot():
    store = FakeStore()
    content = _session() + _title("baseline") + _title("dc-01")
    ingest_out_file(store, "red-01", content)
    assert store.recorded == [("red-01", "dc-01")]


def test_ingest_out_file_no_pivot_records_nothing():
    store = FakeStore()
    content = _session() + _title("baseline") + _title("baseline")
    ingest_out_file(store, "red-01", content)
    assert store.recorded == []


def test_breach_detector_poll_once_reads_red_out_files_only(tmp_path):
    (tmp_path / "red-01.out").write_text(_session() + _title("baseline") + _title("dc-01"), encoding="utf-8")
    # 藍隊的 .out 不該被這支程式碰——只監看紅隊有沒有 pivot 到別的機器。
    (tmp_path / "blue-a-01.out").write_text(_session("blue-a-01") + _title("x") + _title("y"), encoding="utf-8")

    store = FakeStore()
    detector = BreachDetector(str(tmp_path), store)
    detector._poll_once()

    assert store.recorded == [("red-01", "dc-01")]


def test_breach_detector_poll_once_missing_dir_does_not_raise(tmp_path):
    store = FakeStore()
    detector = BreachDetector(str(tmp_path / "does-not-exist"), store)
    detector._poll_once()
    assert store.recorded == []


def test_breach_detector_poll_once_idempotent_across_polls(tmp_path):
    # 同一份檔案被重複整份重讀（設計如此，見 BreachDetector docstring），
    # 重複 poll 不該重複記錄同一個 pivot。
    path = tmp_path / "red-01.out"
    path.write_text(_session() + _title("baseline") + _title("dc-01"), encoding="utf-8")

    store = FakeStore()
    detector = BreachDetector(str(tmp_path), store)
    detector._poll_once()
    detector._poll_once()

    assert store.recorded == [("red-01", "dc-01")]
