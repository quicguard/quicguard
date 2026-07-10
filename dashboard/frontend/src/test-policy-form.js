// Test script to verify policy form state management
// Run with: node test-policy-form.js

console.log("Testing policy form state management...\n");

// Test 1: Verify polId is removed
const fs = require('fs');
const content = fs.readFileSync('./src/routes/Dashboard.svelte', 'utf8');

// Check that polId is not used as a variable declaration
const polIdDecl = content.match(/let polId\s*=/);
if (polIdDecl) {
  console.log("FAIL: polId variable still declared");
} else {
  console.log("PASS: polId variable removed");
}

// Check that polId is not used in saveWizardPolicy
const savePolicyMatch = content.match(/policy_id:\s*polId/);
if (savePolicyMatch) {
  console.log("FAIL: polId still used in saveWizardPolicy");
} else {
  console.log("PASS: polId not used in saveWizardPolicy");
}

// Test 2: Verify Policy ID input is removed from forms
const policyIdInputs = content.match(/Policy ID.*input/g);
if (policyIdInputs && policyIdInputs.length > 0) {
  console.log("FAIL: Policy ID input still exists in forms");
} else {
  console.log("PASS: Policy ID input removed from forms");
}

// Test 3: Verify cancelEdit resets policy form state
const cancelEditMatch = content.match(/function cancelEdit\(\)\s*\{[\s\S]*?showWizardPolicyForm\s*=\s*false/);
if (cancelEditMatch) {
  console.log("PASS: cancelEdit resets showWizardPolicyForm");
} else {
  console.log("FAIL: cancelEdit does not reset showWizardPolicyForm");
}

// Test 4: Verify Add Policy button resets form
const addPolicyButtons = content.match(/btn-add-sm.*Add Policy/g);
if (addPolicyButtons) {
  const allResetForm = addPolicyButtons.every(btn => 
    btn.includes('editingPolicyIndex = -1') && 
    btn.includes('polName = \'\'') && 
    btn.includes('polEffect = \'Allow\'')
  );
  if (allResetForm) {
    console.log("PASS: Add Policy buttons reset form state");
  } else {
    console.log("FAIL: Some Add Policy buttons don't reset form state");
  }
} else {
  console.log("FAIL: No Add Policy buttons found");
}

// Test 5: Verify editWizardPolicy doesn't set polId
const editWizardMatch = content.match(/function editWizardPolicy[\s\S]*?polId/);
if (editWizardMatch) {
  console.log("FAIL: editWizardPolicy still references polId");
} else {
  console.log("PASS: editWizardPolicy doesn't reference polId");
}

// Test 6: Verify policy_id is auto-generated
const autoGenMatch = content.match(/policy_id:\s*`pol-\$\{Date\.now\(\)\}/);
if (autoGenMatch) {
  console.log("PASS: policy_id is auto-generated with timestamp");
} else {
  console.log("FAIL: policy_id is not auto-generated");
}

// Test 7: Verify App ID is displayed as text, not input
const appIdInputs = content.match(/App ID[\s\S]*?<input/g);
if (appIdInputs && appIdInputs.length > 0) {
  console.log("FAIL: App ID still uses input element");
} else {
  console.log("PASS: App ID displayed as text");
}

console.log("\nAll tests completed!");
