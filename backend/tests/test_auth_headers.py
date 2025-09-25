from backend.core.auth_checks.auth_headers import (
    extract_authentication_metadata,
    parse_authentication_results,
    parse_received_spf,
)


def test_parse_authentication_results_extracts_methods():
    header = (
        "Authentication-Results: mx.example.net; "
        "dkim=pass header.i=@example.net header.s=s1; "
        "spf=fail smtp.mailfrom=baddomain.com; "
        "dmarc=pass action=none"
    )

    results = parse_authentication_results([header])
    assert len(results) == 1
    parsed = results[0]
    assert parsed["authserv_id"] == "mx.example.net"
    methods = {entry["method"]: entry for entry in parsed["results"]}
    assert methods["dkim"]["result"] == "pass"
    assert methods["dkim"]["properties"]["header.i"] == "@example.net"
    assert methods["spf"]["result"] == "fail"
    assert methods["spf"]["properties"]["smtp.mailfrom"] == "baddomain.com"
    assert methods["dmarc"]["properties"]["action"] == "none"


def test_parse_received_spf_captures_comment_and_properties():
    header = (
        "Received-SPF: pass (google.com: domain of sender@example.org designates 1.2.3.4 as permitted sender) "
        "client-ip=1.2.3.4; envelope-from=sender@example.org; helo=mail.example.org"
    )

    parsed = parse_received_spf([header])
    assert parsed == [
        {
            "result": "pass",
            "comment": "google.com: domain of sender@example.org designates 1.2.3.4 as permitted sender",
            "properties": {
                "client-ip": "1.2.3.4",
                "envelope-from": "sender@example.org",
                "helo": "mail.example.org",
            },
        }
    ]


def test_extract_authentication_metadata_combines_headers():
    headers = {
        "Authentication-Results": [
            "Authentication-Results: auth.example; spf=pass smtp.mailfrom=example.com"
        ],
        "ARC-Authentication-Results": [
            "ARC-Authentication-Results: i=1; mx.example; dkim=pass header.d=example.com"
        ],
        "Received-SPF": [
            "Received-SPF: neutral (policy neutral) client-ip=5.6.7.8; envelope-from=example.com"
        ],
    }

    parsed = extract_authentication_metadata(headers)

    assert len(parsed["authentication_results"]) == 2
    assert parsed["authentication_results"][0]["authserv_id"].startswith("auth.example")
    assert parsed["authentication_results"][1]["header"] == "ARC-Authentication-Results"
    assert parsed["received_spf"][0]["result"] == "neutral"
