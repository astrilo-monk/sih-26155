# Testing Strategy

*(Status: Testing framework planned, not yet implemented)*

Since we are dealing with regex and security rules, we absolutely need automated tests so we don't break things while hacking late at night. We will use `pytest`.

## 1. Parser Testing (Fixture-based)
We will have a `tests/fixtures/configs/` directory containing raw `.txt` config snippets (e.g., `cisco_acls.txt`, `fortigate_interfaces.txt`). 
The tests will run the parsers against these snippets and assert that the resulting `NormalizedConfig` fields exactly match our expectations.

## 2. Rule Testing
We will test the rules engine independently of the parsers. We will construct mock `NormalizedConfig` objects (e.g., one with Telnet enabled, one with SSH only) and pass them to the rules engine to assert that the correct `Finding` objects are generated.

## 3. Scoring Testing
Simple unit tests to ensure that the 100-point penalty algorithm calculates correctly and floors at 0.

## 4. AI Mocking
We will use the `unittest.mock` library to mock the Gemini API calls during testing, so our CI/CD (if we set one up) doesn't use up our API quota or fail due to network issues.
