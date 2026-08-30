import json
import unittest
from unittest import mock

from evoagent.llm import JsonChatClient
from evoagent.telemetry import ExecutionLedger


class FakeResponse:
    def __init__(self, content):
        self.payload = json.dumps({
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 3},
        }).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class JsonChatClientTests(unittest.TestCase):
    @mock.patch("evoagent.llm.urllib.request.urlopen")
    def test_invalid_structured_output_is_retried_and_accounted(self, urlopen):
        urlopen.side_effect = [FakeResponse('{"action":"final" "findings":[]}'), FakeResponse(
            '{"action":"final","findings":[]}'
        )]
        ledger = ExecutionLedger("test")
        client = JsonChatClient("https://example.test", "secret", "model")

        result = client.complete_json("lead", "system", "task", ledger)

        self.assertEqual("final", result["action"])
        self.assertEqual(2, urlopen.call_count)
        calls = ledger.summary()["model_call_log"]
        self.assertFalse(calls[0]["ok"])
        self.assertTrue(calls[1]["ok"])
        retry_payload = json.loads(urlopen.call_args_list[1].args[0].data.decode("utf-8"))
        self.assertIn("not valid JSON", retry_payload["messages"][-1]["content"])

    @mock.patch("evoagent.llm.urllib.request.urlopen")
    def test_json_markdown_fence_is_removed_locally(self, urlopen):
        urlopen.return_value = FakeResponse('```json\n{"action":"final"}\n```')
        client = JsonChatClient("https://example.test", "secret", "model")

        self.assertEqual("final", client.complete_json("lead", "system", "task")["action"])
        self.assertEqual(1, urlopen.call_count)


if __name__ == "__main__":
    unittest.main()
