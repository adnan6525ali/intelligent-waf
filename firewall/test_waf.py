"""
End-to-End WAF Test Suite
Tests the Flask WAF with various HTTP request types
Run: python3 test_waf.py (while app.py is running)
"""

import requests
import json
import time

BASE_URL = "http://localhost:5001"

# ── Test Cases ────────────────────────────────────────────────────
test_cases = [
    # Normal Traffic — should ALL be ALLOWED
    {
        "name"    : "Normal GET request",
        "method"  : "GET",
        "url"     : "/shop/index.jsp?page=home",
        "content" : "",
        "expected": "ALLOWED"
    },
    {
        "name"    : "Normal POST login",
        "method"  : "POST",
        "url"     : "/shop/login",
        "content" : "username=john&password=secret123",
        "expected": "ALLOWED"
    },
    {
        "name"    : "Normal search",
        "method"  : "GET",
        "url"     : "/shop/search?q=laptop",
        "content" : "",
        "expected": "ALLOWED"
    },
    # Attack Traffic — should ALL be BLOCKED
    {
        "name"    : "SQL Injection — UNION SELECT",
        "method"  : "POST",
        "url"     : "/shop/login",
        "content" : "id=1 UNION SELECT username,password FROM users--",
        "expected": "BLOCKED"
    },
    {
        "name"    : "SQL Injection — OR 1=1",
        "method"  : "POST",
        "url"     : "/shop/login",
        "content" : "username=admin' OR 1=1 --&password=x",
        "expected": "BLOCKED"
    },
    {
        "name"    : "XSS — script tag",
        "method"  : "POST",
        "url"     : "/shop/search",
        "content" : "q=<script>alert(document.cookie)</script>",
        "expected": "BLOCKED"
    },
    {
        "name"    : "XSS — onerror",
        "method"  : "POST",
        "url"     : "/shop/profile",
        "content" : "name=<img src=x onerror=alert(1)>",
        "expected": "BLOCKED"
    },
    {
        "name"    : "Path Traversal — etc/passwd",
        "method"  : "GET",
        "url"     : "/shop/files",
        "content" : "filename=../../etc/passwd",
        "expected": "BLOCKED"
    },
    {
        "name"    : "Command Injection",
        "method"  : "POST",
        "url"     : "/shop/ping",
        "content" : "host=localhost; cat /etc/passwd",
        "expected": "BLOCKED"
    },
]


# ── Run Tests ─────────────────────────────────────────────────────
def run_tests():
    print("=" * 60)
    print("   INTELLIGENT WAF — END-TO-END TEST SUITE")
    print("=" * 60)

    passed = 0
    failed = 0
    results = []

    for i, test in enumerate(test_cases, 1):
        try:
            resp = requests.post(
                f"{BASE_URL}/inspect",
                json={
                    "url"    : test["url"],
                    "content": test["content"],
                    "method" : test["method"]
                },
                timeout=10
            )
            data   = resp.json()
            status = data.get("status", "UNKNOWN")
            conf   = data.get("confidence", "N/A")

            passed_test = status == test["expected"]
            icon = "✅" if passed_test else "❌"

            if passed_test:
                passed += 1
            else:
                failed += 1

            print(f"\n{icon} Test {i}: {test['name']}")
            print(f"   Expected  : {test['expected']}")
            print(f"   Got       : {status}")
            print(f"   Confidence: {conf}")

            results.append({
                "test"    : test["name"],
                "expected": test["expected"],
                "got"     : status,
                "passed"  : passed_test,
                "confidence": conf
            })

        except Exception as e:
            print(f"\n❌ Test {i}: {test['name']} — ERROR: {e}")
            failed += 1

        time.sleep(0.3)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print(f"   TEST SUMMARY")
    print("=" * 60)
    print(f"   Total Tests : {total}")
    print(f"   Passed      : {passed} ✅")
    print(f"   Failed      : {failed} ❌")
    print(f"   Pass Rate   : {round(passed/total*100, 1)}%")
    print("=" * 60)

    if failed == 0:
        print("\n🎉 ALL TESTS PASSED — WAF is working correctly!")
    else:
        print(f"\n⚠️  {failed} test(s) failed — review above")

    return results


if __name__ == "__main__":
    print("Starting WAF tests...")
    print("Make sure app.py is running on localhost:5000\n")
    time.sleep(1)
    run_tests()