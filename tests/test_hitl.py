"""Unit tests for soc_triage/hitl.py (ApprovalQueue)."""

import threading

import pytest

from soc_triage.hitl import ApprovalQueue
from factories import make_alert, make_result


def result(alert_id="a1", status="pending_approval"):
    return make_result(status=status, alert=make_alert(event_id=alert_id))


class TestPendingQueue:
    def test_starts_empty(self):
        assert ApprovalQueue().pending() == []

    def test_enqueue_then_pending(self):
        q = ApprovalQueue()
        r = result("a1")
        q.enqueue(r)
        assert q.pending() == [r]

    def test_same_alert_id_is_overwritten_not_duplicated(self):
        q = ApprovalQueue()
        q.enqueue(result("a1", "first"))
        q.enqueue(result("a1", "second"))
        assert [r.status for r in q.pending()] == ["second"]

    def test_pending_returns_a_copy_of_the_list(self):
        q = ApprovalQueue()
        q.enqueue(result("a1"))
        q.pending().clear()
        assert len(q.pending()) == 1

    def test_pending_preserves_insertion_order(self):
        q = ApprovalQueue()
        for i in ("a", "b", "c"):
            q.enqueue(result(i))
        assert [r.alert_id for r in q.pending()] == ["a", "b", "c"]

    def test_approve_removes_from_queue_and_stamps_status(self):
        q = ApprovalQueue()
        q.enqueue(result("a1"))
        out = q.approve("a1", "dana")
        assert out.status == "approved_by:dana" and q.pending() == []

    def test_reject_removes_from_queue_and_stamps_status(self):
        q = ApprovalQueue()
        q.enqueue(result("a1"))
        assert q.reject("a1", "dana").status == "rejected_by:dana"
        assert q.pending() == []

    def test_approve_does_not_mutate_the_stored_original(self):
        q = ApprovalQueue()
        original = result("a1")
        q.enqueue(original)
        q.approve("a1", "dana")
        assert original.status == "pending_approval"

    @pytest.mark.parametrize("method", ["approve", "reject"])
    def test_unknown_alert_raises_key_error(self, method):
        with pytest.raises(KeyError):
            getattr(ApprovalQueue(), method)("missing", "dana")

    @pytest.mark.parametrize("method", ["approve", "reject"])
    def test_an_alert_cannot_be_decided_twice(self, method):
        q = ApprovalQueue()
        q.enqueue(result("a1"))
        getattr(q, method)("a1", "dana")
        with pytest.raises(KeyError):
            getattr(q, method)("a1", "dana")

    def test_only_the_named_alert_is_removed(self):
        q = ApprovalQueue()
        q.enqueue(result("a1"))
        q.enqueue(result("a2"))
        q.approve("a1", "dana")
        assert [r.alert_id for r in q.pending()] == ["a2"]


class TestReviewQueue:
    def test_starts_empty(self):
        assert ApprovalQueue().review() == []

    def test_add_review_then_review(self):
        q = ApprovalQueue()
        r = result("a1", "escalated")
        q.add_review(r)
        assert q.review() == [r]

    def test_review_returns_a_copy_of_the_list(self):
        q = ApprovalQueue()
        q.add_review(result("a1"))
        q.review().clear()
        assert len(q.review()) == 1

    def test_acknowledge_removes_and_stamps_status(self):
        q = ApprovalQueue()
        q.add_review(result("a1", "escalated"))
        out = q.acknowledge("a1", "sam")
        assert out.status == "acknowledged_by:sam" and q.review() == []

    def test_acknowledge_unknown_alert_raises_key_error(self):
        with pytest.raises(KeyError):
            ApprovalQueue().acknowledge("missing", "sam")

    def test_same_alert_id_is_overwritten(self):
        q = ApprovalQueue()
        q.add_review(result("a1", "first"))
        q.add_review(result("a1", "second"))
        assert [r.status for r in q.review()] == ["second"]


class TestTheTwoQueuesAreIndependent:
    def test_an_alert_in_review_cannot_be_approved(self):
        q = ApprovalQueue()
        q.add_review(result("a1"))
        with pytest.raises(KeyError):
            q.approve("a1", "dana")

    def test_an_alert_pending_approval_cannot_be_acknowledged(self):
        q = ApprovalQueue()
        q.enqueue(result("a1"))
        with pytest.raises(KeyError):
            q.acknowledge("a1", "sam")

    def test_same_id_can_live_in_both_queues(self):
        q = ApprovalQueue()
        q.enqueue(result("a1"))
        q.add_review(result("a1"))
        assert len(q.pending()) == 1 and len(q.review()) == 1


def test_concurrent_enqueue_loses_nothing():
    q = ApprovalQueue()

    def work(n):
        for i in range(50):
            q.enqueue(result(f"t{n}-{i}"))

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(q.pending()) == 8 * 50
