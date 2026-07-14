use std::collections::HashSet;

use konfig::*;

fn test_claims(sub: &str, org_id: &str) -> TokenClaims {
    TokenClaims {
        sub: sub.to_string(),
        org_id: org_id.to_string(),
        app: String::new(),
        roles: vec![],
        permissions: vec![],
        iss: None,
        aud: None,
        exp: None,
        iat: None,
    }
}

#[test]
fn test_condition_equals() {
    let condition = Condition {
        claim: "org_id".to_string(),
        operator: ConditionOperator::Equals,
        value: "org1".to_string(),
    };

    let claims = test_claims("user1", "org1");
    assert!(condition.evaluate(&claims));

    let claims = test_claims("user1", "org2");
    assert!(!condition.evaluate(&claims));
}

#[test]
fn test_condition_not_equals() {
    let condition = Condition {
        claim: "org_id".to_string(),
        operator: ConditionOperator::NotEquals,
        value: "org1".to_string(),
    };

    let claims = test_claims("user1", "org2");
    assert!(condition.evaluate(&claims));

    let claims = test_claims("user1", "org1");
    assert!(!condition.evaluate(&claims));
}

#[test]
fn test_condition_contains() {
    let condition = Condition {
        claim: "sub".to_string(),
        operator: ConditionOperator::Contains,
        value: "admin".to_string(),
    };

    let claims = test_claims("admin_user", "org1");
    assert!(condition.evaluate(&claims));

    let claims = test_claims("user_admin", "org1");
    assert!(condition.evaluate(&claims));

    let claims = test_claims("regular_user", "org1");
    assert!(!condition.evaluate(&claims));
}

#[test]
fn test_condition_starts_with() {
    let condition = Condition {
        claim: "sub".to_string(),
        operator: ConditionOperator::StartsWith,
        value: "service-".to_string(),
    };

    let claims = test_claims("service-backend", "org1");
    assert!(condition.evaluate(&claims));

    let claims = test_claims("backend-service", "org1");
    assert!(!condition.evaluate(&claims));
}

#[test]
fn test_condition_in() {
    let condition = Condition {
        claim: "org_id".to_string(),
        operator: ConditionOperator::In,
        value: "org1,org2,org3".to_string(),
    };

    let claims = test_claims("user1", "org2");
    assert!(condition.evaluate(&claims));

    let claims = test_claims("user1", "org4");
    assert!(!condition.evaluate(&claims));
}

#[test]
fn test_condition_not_in() {
    let condition = Condition {
        claim: "org_id".to_string(),
        operator: ConditionOperator::NotIn,
        value: "blocked_org,banned_org".to_string(),
    };

    let claims = test_claims("user1", "org1");
    assert!(condition.evaluate(&claims));

    let claims = test_claims("user1", "blocked_org");
    assert!(!condition.evaluate(&claims));
}

#[test]
fn test_condition_unknown_claim() {
    let condition = Condition {
        claim: "unknown_field".to_string(),
        operator: ConditionOperator::Equals,
        value: "anything".to_string(),
    };

    let claims = test_claims("user1", "org1");
    assert!(!condition.evaluate(&claims));
}

#[test]
fn test_policy_allow_matches() {
    let policy = Policy {
        id: "p1".to_string(),
        name: "Allow GET users".to_string(),
        rules: vec![PolicyRule {
            methods: HashSet::from([HttpMethod::Get]),
            conditions: vec![],
        }],
        effect: PolicyEffect::Allow,
    };

    let claims = test_claims("user1", "org1");
    assert!(policy.matches_request(&HttpMethod::Get, &claims));
    assert!(!policy.matches_request(&HttpMethod::Post, &claims));
}

#[test]
fn test_policy_deny_matches() {
    let policy = Policy {
        id: "p1".to_string(),
        name: "Deny DELETE users".to_string(),
        rules: vec![PolicyRule {
            methods: HashSet::from([HttpMethod::Delete]),
            conditions: vec![],
        }],
        effect: PolicyEffect::Deny,
    };

    let claims = test_claims("user1", "org1");
    assert!(policy.matches_request(&HttpMethod::Delete, &claims));
    assert!(!policy.matches_request(&HttpMethod::Get, &claims));
}

#[test]
fn test_policy_deny_effect_inverts_logic() {
    let policy = Policy {
        id: "p1".to_string(),
        name: "Deny all users".to_string(),
        rules: vec![PolicyRule {
            methods: HashSet::from([HttpMethod::Get]),
            conditions: vec![],
        }],
        effect: PolicyEffect::Deny,
    };

    let claims = test_claims("user1", "org1");
    assert!(policy.matches_request(&HttpMethod::Get, &claims));
}

#[test]
fn test_policy_with_condition() {
    let policy = Policy {
        id: "p1".to_string(),
        name: "Allow only specific org".to_string(),
        rules: vec![PolicyRule {
            methods: HashSet::from([HttpMethod::Get]),
            conditions: vec![Condition {
                claim: "org_id".to_string(),
                operator: ConditionOperator::Equals,
                value: "org1".to_string(),
            }],
        }],
        effect: PolicyEffect::Allow,
    };

    let claims = test_claims("user1", "org1");
    assert!(policy.matches_request(&HttpMethod::Get, &claims));

    let claims = test_claims("user1", "org2");
    assert!(!policy.matches_request(&HttpMethod::Get, &claims));
}

#[test]
fn test_policy_multiple_rules() {
    let policy = Policy {
        id: "p1".to_string(),
        name: "Allow GET or POST".to_string(),
        rules: vec![
            PolicyRule {
                methods: HashSet::from([HttpMethod::Get]),
                conditions: vec![],
            },
            PolicyRule {
                methods: HashSet::from([HttpMethod::Post]),
                conditions: vec![],
            },
        ],
        effect: PolicyEffect::Allow,
    };

    let claims = test_claims("user1", "org1");
    assert!(policy.matches_request(&HttpMethod::Get, &claims));
    assert!(policy.matches_request(&HttpMethod::Post, &claims));
    assert!(!policy.matches_request(&HttpMethod::Delete, &claims));
}

#[test]
fn test_policy_multiple_conditions_all_must_pass() {
    let policy = Policy {
        id: "p1".to_string(),
        name: "Allow specific org and sub".to_string(),
        rules: vec![PolicyRule {
            methods: HashSet::from([HttpMethod::Get]),
            conditions: vec![
                Condition {
                    claim: "org_id".to_string(),
                    operator: ConditionOperator::Equals,
                    value: "org1".to_string(),
                },
                Condition {
                    claim: "sub".to_string(),
                    operator: ConditionOperator::StartsWith,
                    value: "admin-".to_string(),
                },
            ],
        }],
        effect: PolicyEffect::Allow,
    };

    let claims = test_claims("admin-user", "org1");
    assert!(policy.matches_request(&HttpMethod::Get, &claims));

    let claims = test_claims("regular-user", "org1");
    assert!(!policy.matches_request(&HttpMethod::Get, &claims));

    let claims = test_claims("admin-user", "org2");
    assert!(!policy.matches_request(&HttpMethod::Get, &claims));
}

#[test]
fn test_policy_empty_rules() {
    let policy = Policy {
        id: "p1".to_string(),
        name: "Empty policy".to_string(),
        rules: vec![],
        effect: PolicyEffect::Allow,
    };

    let claims = test_claims("user1", "org1");
    assert!(!policy.matches_request(&HttpMethod::Get, &claims));
}

#[test]
fn test_policy_default_effect_is_allow() {
    let policy: Policy = serde_json::from_str(
        r#"{
            "id": "p1",
            "name": "Test",
            "rules": []
        }"#,
    )
    .unwrap();

    assert!(matches!(policy.effect, PolicyEffect::Allow));
}
