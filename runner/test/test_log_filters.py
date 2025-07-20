import logging
from runner.src import log_filters


def test_exclude_log_filter(monkeypatch):
    """
    Test the ExcludeFilter to ensure it correctly filters out specified log messages.
    """
    # Create an instance of the ExcludeFilter with a message to exclude
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        "test.py",
        10,
        "",
        None,
        None,
        None,
        None,
    )
    monkeypatch.setattr(record, "getMessage", lambda: "GET /test HTTP/1.1 200 OK")
    exclude_filter = log_filters.ExcludeFilter()
    assert exclude_filter.filter(record)

    monkeypatch.setattr(record, "getMessage", lambda: "GET /health HTTP/1.1 200 OK")
    exclude_filter = log_filters.ExcludeFilter(exclude_messages=["/health"])
    assert not exclude_filter.filter(record)
