import pytest
from backend.ingestion.error_policy import safe_call, safe_getattr, safe_method_call


class TestSafeCall:
    """Test cases for safe_call function."""

    def test_safe_call_success(self):
        """Test safe_call with a successful function call."""

        def add(x, y):
            return x + y

        result = safe_call(add, 2, 3)
        assert result == 5

    def test_safe_call_with_exception(self):
        """Test safe_call with a function that raises an exception."""

        def failing_function():
            raise ValueError("Test exception")

        result = safe_call(failing_function, default="fallback")
        assert result == "fallback"

    def test_safe_call_no_default(self):
        """Test safe_call with no default value."""

        def failing_function():
            raise ValueError("Test exception")

        result = safe_call(failing_function)
        assert result is None

    def test_safe_call_with_kwargs(self):
        """Test safe_call with keyword arguments."""

        def multiply(x, y, factor=1):
            return x * y * factor

        result = safe_call(multiply, 2, 3, factor=2)
        assert result == 12

    def test_safe_call_kwargs_failure(self):
        """Test safe_call with failing function using kwargs."""

        def failing_function(x, factor=1):
            raise ValueError("Test exception")

        result = safe_call(failing_function, 5, default=0, factor=2)
        assert result == 0


class TestSafeGetattr:
    """Test cases for safe_getattr function."""

    def test_safe_getattr_success(self):
        """Test safe_getattr with existing attribute."""

        class TestObject:
            value = 42

        obj = TestObject()
        result = safe_getattr(obj, "value")
        assert result == 42

    def test_safe_getattr_missing_attribute(self):
        """Test safe_getattr with non-existing attribute."""

        class TestObject:
            value = 42

        obj = TestObject()
        result = safe_getattr(obj, "missing", default="default_value")
        assert result == "default_value"

    def test_safe_getattr_no_default(self):
        """Test safe_getattr with no default value."""

        class TestObject:
            pass

        obj = TestObject()
        result = safe_getattr(obj, "nonexistent")
        assert result is None

    def test_safe_getattr_with_exception_property(self):
        """Test safe_getattr with property that raises exception."""

        class TestObject:
            @property
            def failing_prop(self):
                raise AttributeError("Failing property")

        obj = TestObject()
        result = safe_getattr(obj, "failing_prop", default="safe")
        assert result == "safe"


class TestSafeMethodCall:
    """Test cases for safe_method_call function."""

    def test_safe_method_call_success(self):
        """Test safe_method_call with existing method."""

        class TestObject:
            def add(self, x, y):
                return x + y

        obj = TestObject()
        result = safe_method_call(obj, "add", 2, 3)
        assert result == 5

    def test_safe_method_call_missing_method(self):
        """Test safe_method_call with non-existing method."""

        class TestObject:
            pass

        obj = TestObject()
        result = safe_method_call(obj, "missing_method", default="fallback")
        assert result == "fallback"

    def test_safe_method_call_no_default(self):
        """Test safe_method_call with no default value."""

        class TestObject:
            pass

        obj = TestObject()
        result = safe_method_call(obj, "nonexistent")
        assert result is None

    def test_safe_method_call_with_exception(self):
        """Test safe_method_call with method that raises exception."""

        class TestObject:
            def failing_method(self):
                raise ValueError("Method failed")

        obj = TestObject()
        result = safe_method_call(obj, "failing_method", default="safe_result")
        assert result == "safe_result"

    def test_safe_method_call_with_kwargs(self):
        """Test safe_method_call with keyword arguments."""

        class TestObject:
            def process(self, x, multiplier=1):
                return x * multiplier

        obj = TestObject()
        result = safe_method_call(obj, "process", 5, multiplier=3)
        assert result == 15

    def test_safe_method_call_kwargs_failure(self):
        """Test safe_method_call with failing method using kwargs."""

        class TestObject:
            def failing_method(self, x, factor=1):
                raise RuntimeError("Method failed")

        obj = TestObject()
        result = safe_method_call(obj, "failing_method", 10, default=0, factor=2)
        assert result == 0

    def test_safe_method_call_empty_method(self):
        """Test safe_method_call with empty method name."""

        class TestObject:
            def test_method(self):
                return "success"

        obj = TestObject()
        result = safe_method_call(obj, "", default="empty")
        assert result == "empty"
