from voidrecon.utils import net


def test_is_ip_and_cidr():
    assert net.is_ip("8.8.8.8")
    assert not net.is_ip("example.com")
    assert net.is_cidr("10.0.0.0/8")
    assert not net.is_cidr("10.0.0.0")


def test_is_domain():
    assert net.is_domain("sub.example.com")
    assert not net.is_domain("8.8.8.8")
    assert not net.is_domain("not a domain")


def test_normalize_host():
    assert net.normalize_host("HTTPS://Sub.Example.com:8443/path") == "sub.example.com"
    assert net.normalize_host("*.example.com") == "example.com"
    assert net.normalize_host("example.com.") == "example.com"


def test_registrable_domain():
    assert net.registrable_domain("a.b.example.com") == "example.com"
    assert net.registrable_domain("x.example.co.uk") == "example.co.uk"
    assert net.registrable_domain("example.com") == "example.com"


def test_is_subdomain_of():
    assert net.is_subdomain_of("dev.example.com", "example.com")
    assert net.is_subdomain_of("example.com", "example.com")
    assert not net.is_subdomain_of("evil-example.com", "example.com")


def test_ip_in_cidr():
    assert net.ip_in_cidr("10.1.2.3", "10.0.0.0/8")
    assert not net.ip_in_cidr("192.168.1.1", "10.0.0.0/8")
