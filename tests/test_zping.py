from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from zinoargus.zping import ZpingError, get_zino_uptime

PATCH_GET_CMD = "zinoargus.zping.getCmd"


class TestGetZinoUptime:
    @patch(PATCH_GET_CMD, new_callable=AsyncMock)
    def test_when_agent_responds_it_should_return_uptime_as_int(self, mock_get_cmd):
        mock_value = MagicMock()
        mock_value.__int__ = lambda self: 42
        mock_get_cmd.return_value = (None, None, None, [("oid", mock_value)])

        result = get_zino_uptime()

        assert result == 42

    @patch(PATCH_GET_CMD, new_callable=AsyncMock)
    def test_when_error_indication_it_should_raise_zping_error(self, mock_get_cmd):
        mock_get_cmd.return_value = ("requestTimedOut", None, None, [])

        with pytest.raises(ZpingError, match="requestTimedOut"):
            get_zino_uptime()

    @patch(PATCH_GET_CMD, new_callable=AsyncMock)
    def test_when_error_status_it_should_raise_zping_error(self, mock_get_cmd):
        mock_status = MagicMock()
        mock_status.__bool__ = lambda self: True
        mock_status.prettyPrint.return_value = "noSuchName"
        mock_get_cmd.return_value = (
            None,
            mock_status,
            1,
            [("1.3.6.1", MagicMock())],
        )

        with pytest.raises(ZpingError, match="SNMP error"):
            get_zino_uptime()

    @patch(PATCH_GET_CMD, new_callable=AsyncMock)
    def test_when_empty_response_it_should_raise_zping_error(self, mock_get_cmd):
        mock_get_cmd.return_value = (None, None, None, [])

        with pytest.raises(ZpingError, match="Empty response"):
            get_zino_uptime()

    @patch(PATCH_GET_CMD, new_callable=AsyncMock)
    def test_when_exception_raised_it_should_raise_zping_error(self, mock_get_cmd):
        mock_get_cmd.side_effect = RuntimeError("connection failed")

        with pytest.raises(ZpingError, match="SNMP request failed"):
            get_zino_uptime()
