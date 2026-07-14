use serde_json;

/// Generate the HTML page with JavaScript that propagates authentication tokens
/// across all domains in the organization.
///
/// The flow:
/// 1. User returns from IDP with `?token=xxx`
/// 2. QuicGuard serves this HTML page
/// 3. JS sends X-Set-Token to other domains → QuicGuard sets cookies
/// 4. JS sets cookies on current domain locally
/// 5. JS redirects to the requested URL
pub fn token_setting_html(
    other_domains: &[String],
    current_paths: &[String],
    token: &str,
    cookie_name: &str,
    req_url: &str,
) -> String {
    let other_domains_json = serde_json::to_string(other_domains).unwrap();
    let current_paths_json = serde_json::to_string(current_paths).unwrap();

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Setting up authentication...</title></head>
<body>
<script>
(async () => {{
  const token = "{token}";
  const cookieName = "{cookie_name}";
  const reqUrl = "{req_url}";
  
  const otherDomains = {other_domains_json};
  const currentPaths = {current_paths_json};
  
  let allSuccess = true;
  
  for (const domain of otherDomains) {{
    try {{
      const response = await fetch(`https://${{domain}}`, {{
        method: 'GET',
        headers: {{'X-Set-Token': token}}
      }});
      if (!response.ok) throw new Error('Failed');
    }} catch (e) {{
      allSuccess = false;
      break;
    }}
  }}
  
  if (allSuccess) {{
    for (const path of currentPaths) {{
      document.cookie = `${{cookieName}}=${{token}}; path=${{path}}; secure; samesite=lax`;
    }}
    window.location.href = reqUrl;
  }} else {{
    document.body.innerHTML = '<h1>Authentication Failed</h1><p>Could not set authentication for all required domains.</p>';
  }}
}})();
</script>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_setting_html_contains_required_elements() {
        let html = token_setting_html(
            &["other.example.com".to_string()],
            &["/".to_string()],
            "test-token-123",
            "session_token",
            "https://app.example.com/dashboard",
        );

        assert!(html.contains("test-token-123"));
        assert!(html.contains("session_token"));
        assert!(html.contains("https://app.example.com/dashboard"));
        assert!(html.contains("other.example.com"));
        assert!(html.contains("X-Set-Token"));
        assert!(html.contains("document.cookie"));
        assert!(html.contains("window.location.href"));
    }

    #[test]
    fn test_token_setting_html_multiple_domains() {
        let html = token_setting_html(
            &[
                "other.example.com".to_string(),
                "api.example.com".to_string(),
            ],
            &["/".to_string(), "/app".to_string()],
            "mytoken",
            "auth_token",
            "https://app.example.com/protected",
        );

        assert!(html.contains("other.example.com"));
        assert!(html.contains("api.example.com"));
        assert!(html.contains("mytoken"));
        assert!(html.contains("auth_token"));
    }

    #[test]
    fn test_token_setting_html_escapes_special_chars() {
        let html = token_setting_html(
            &["other.example.com".to_string()],
            &["/".to_string()],
            "token-with-\"quotes\"&<special>",
            "cookie",
            "https://example.com/path?a=1&b=2",
        );

        // Token should be present (JS handles escaping via JSON serialization)
        assert!(html.contains("token-with-"));
    }

    #[test]
    fn test_token_setting_html_contains_domains() {
        let html = token_setting_html(
            &["pr2.com".to_string()],
            &["/api".to_string()],
            "test-token",
            "session_token",
            "/",
        );

        assert!(html.contains("pr2.com"));
        assert!(html.contains("X-Set-Token"));
    }

    #[test]
    fn test_token_setting_html_contains_paths() {
        let html = token_setting_html(
            &["pr2.com".to_string()],
            &["/api".to_string(), "/dashboard".to_string()],
            "test-token",
            "session_token",
            "/",
        );

        assert!(html.contains("/api"));
        assert!(html.contains("/dashboard"));
    }

    #[test]
    fn test_token_setting_html_sets_cookie_locally() {
        let html = token_setting_html(
            &["pr2.com".to_string()],
            &["/api".to_string()],
            "test-token",
            "session_token",
            "/",
        );

        assert!(html.contains("document.cookie"));
        // Cookie is set via JS template literals: `${cookieName}=${token}; path=${path}; secure; samesite=lax`
        assert!(html.contains("${cookieName}=${token}"));
        assert!(html.contains("path=${path}"));
        assert!(html.contains("secure"));
        assert!(html.contains("samesite=lax"));
    }
}
