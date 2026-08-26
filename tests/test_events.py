from core.events import EventBus


class TestEventBus:
    def test_on_and_emit(self):
        bus = EventBus()
        results = []

        def handler(**kwargs):
            results.append(kwargs)

        bus.on("test_event", handler)
        bus.emit("test_event", foo="bar")

        assert len(results) == 1
        assert results[0]["foo"] == "bar"

    def test_multiple_handlers(self):
        bus = EventBus()
        count = [0, 0]

        def handler1(**kwargs):
            count[0] += 1

        def handler2(**kwargs):
            count[1] += 1

        bus.on("event", handler1)
        bus.on("event", handler2)
        bus.emit("event")

        assert count[0] == 1
        assert count[1] == 1

    def test_off_removes_handler(self):
        bus = EventBus()
        results = []

        def handler(**kwargs):
            results.append(kwargs)

        bus.on("event", handler)
        bus.off("event", handler)
        bus.emit("event")

        assert results == []

    def test_emit_unknown_event_no_error(self):
        bus = EventBus()
        bus.emit("nonexistent_event")

    def test_handler_exception_caught(self):
        bus = EventBus()

        def bad_handler(**kwargs):
            raise ValueError("test error")

        bus.on("event", bad_handler)
        bus.emit("event")

    def test_multiple_emits(self):
        bus = EventBus()
        count = 0

        def counter(**kwargs):
            nonlocal count
            count += 1

        bus.on("inc", counter)
        bus.emit("inc")
        bus.emit("inc")
        bus.emit("inc")
        assert count == 3