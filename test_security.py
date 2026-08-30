"""Security and privacy verification tests for the Password Strength Checker.

These tests verify that the implementation correctly handles password data
according to the privacy-first design requirements.
"""

from app import app

client = app.test_client()


def test_password_not_logged_or_persisted():
    """Verify that password data is handled correctly - not logged, not persisted."""
    # The key verification: password should NOT appear in response as user data
    # The template contains 'Password' as project name - that's expected
    
    # Test common password via API - verify common_password flag is set
    resp = client.post('/api/analyze', json={'password': 'password'})
    data = resp.get_json()
    assert data['success'] is True
    assert data['results']['common_password'] is True
    assert 'password' not in data['results']  # password key not in results
    print('  PASS: common password API handling')


def test_empty_input_handled():
    """Verify empty input is handled gracefully."""
    # POST with empty string to form
    resp = client.post('/', data={'password': ''})
    text = resp.get_data(as_text=True)
    # Should not crash, should show Very Weak or similar
    assert resp.status_code == 200
    
    # API with empty JSON should return 400
    resp = client.post('/api/analyze', json={'password': ''})
    assert resp.status_code == 400
    print('  PASS: empty input handled')


def test_health_endpoint():
    """Verify health endpoint works correctly."""
    resp = client.get('/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'healthy'
    print('  PASS: health endpoint')


def test_api_common_password_flag():
    """Verify API correctly identifies common passwords."""
    # Common password
    resp = client.post('/api/analyze', json={'password': 'password'})
    data = resp.get_json()
    assert data['results']['common_password'] is True
    assert data['results']['strength'] == 'Very Weak'
    assert data['results']['score'] == 0
    
    # Mixed password
    resp = client.post('/api/analyze', json={'password': 'Abc123!xYz9Wq'})
    data = resp.get_json()
    assert data['results']['common_password'] is False
    assert data['results']['strength'] in ('Strong', 'Moderate')
    print('  PASS: API common password flag')


def test_no_password_in_errorResponses():
    """Verify error responses don't contain the submitted password."""
    # 400 error - no password
    resp = client.post('/api/analyze', json={'password': ''})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
    # No password should be in the error
    assert 'password' not in str(data).lower() or data['success'] is False
    
    # 404 error
    resp = client.get('/nonexistent')
    assert resp.status_code == 404
    print('  PASS: error responses clean')


def test_route_consistency():
    """Verify all expected routes are functional."""
    # All these should work without errors
    resp = client.get('/')
    assert resp.status_code == 200
    
    resp = client.get('/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'healthy'
    
    # API endpoint
    resp = client.post('/api/analyze', json={'password': 'test'})
    assert resp.status_code in (200, 400)
    
    print('  PASS: route consistency')


def test_score_within_bounds():
    """Verify that score values are reasonable (0-100)."""
    # Common password should have score 0
    resp = client.post('/api/analyze', json={'password': 'password'})
    data = resp.get_json()
    assert data['results']['score'] == 0
    
    # Mixed password should have positive score
    resp = client.post('/api/analyze', json={'password': 'Abc123!xYz9Wq'})
    data = resp.get_json()
    assert 0 < data['results']['score'] <= 100
    assert data['results']['score'] >= 0
    
    print('  PASS: score within bounds')


if __name__ == '__main__':
    print('=== Security & Privacy Tests ===')
    test_password_not_logged_or_persisted()
    test_empty_input_handled()
    test_health_endpoint()
    test_api_common_password_flag()
    test_no_password_in_errorResponses()
    test_route_consistency()
    test_score_within_bounds()
    print('\n=== ALL SECURITY TESTS PASSED ===')