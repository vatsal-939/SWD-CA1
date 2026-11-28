import pytest
from app.database import query_db

def login_as(client, username, password):
    """Helper to authenticate test client as a specific user."""
    return client.post('/auth/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


def test_doctor_create_medical_record(client, app):
    """Verify that a doctor can successfully create a new medical record."""
    login_as(client, 'dr_smith', 'DoctorPass123!@#')

    # Retrieve a valid patient ID
    with app.app_context():
        patient = query_db("SELECT id FROM users WHERE role = 'patient' LIMIT 1", one=True)
        patient_id = str(patient['id'])

    response = client.post('/records/create', data={
        'patient_id': patient_id,
        'diagnosis': 'Acute Bronchitis',
        'treatment_notes': 'Persistent cough for 5 days. Prescribed rest and fluids.',
        'prescription': 'Amoxicillin 500mg tid x 7 days'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Medical record created successfully" in response.data
    assert b"Acute Bronchitis" in response.data


def test_patient_can_only_read_own_records(client):
    """Verify patient views only their own records and not other patients' records."""
    # john_doe (patient) logs in
    login_as(client, 'john_doe', 'PatientPass123!@#')

    response = client.get('/records/')
    assert response.status_code == 200
    # John's diagnosis from seed is Hypertension
    assert b"Hypertension (Stage 1)" in response.data
    # Jane's diagnosis from seed is Allergic Rhinitis; John must NOT see it
    assert b"Seasonal Allergic Rhinitis" not in response.data


def test_idor_blocked_on_view_record(client):
    """
    IDOR Security Test:
    Verify that patient 'john_doe' attempting to access record #2
    (belonging to 'jane_roe') receives 403 Forbidden.
    """
    login_as(client, 'john_doe', 'PatientPass123!@#')

    # Record 2 belongs to jane_roe
    response = client.get('/records/view/2')
    assert response.status_code == 403
    assert b"Access Denied" in response.data


def test_doctor_edit_record_success(client):
    """Verify doctor can edit records authored by them."""
    login_as(client, 'dr_smith', 'DoctorPass123!@#')

    # Record 1 was authored by dr_smith
    response = client.post('/records/edit/1', data={
        'diagnosis': 'Hypertension (Controlled)',
        'treatment_notes': 'Blood pressure stabilized at 120/80. Continue regimen.',
        'prescription': 'Lisinopril 10mg once daily.'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Medical record updated successfully" in response.data
    assert b"Hypertension (Controlled)" in response.data


def test_doctor_cannot_edit_other_doctors_record(client, app):
    """Verify doctor cannot tamper with another doctor's consultation notes (RBAC/IDOR)."""
    with app.app_context():
        # Create a record authored by dr_patel (ID 3)
        from app.database import execute_db
        rec_id, _ = execute_db(
            """
            INSERT INTO medical_records (patient_id, doctor_id, diagnosis, treatment_notes, prescription)
            VALUES (4, 3, 'Migraine', 'Rest in dark room', 'Sumatriptan 50mg')
            """
        )

    # Log in as dr_smith (ID 2), attempt to edit dr_patel's record
    login_as(client, 'dr_smith', 'DoctorPass123!@#')
    response = client.post(f'/records/edit/{rec_id}', data={
        'diagnosis': 'Tampered Diagnosis',
        'treatment_notes': 'Hacked notes',
        'prescription': 'Hacked prescription'
    })

    assert response.status_code == 403


def test_soft_delete_preserves_audit_trail(client, app):
    """Verify soft-delete hides record from UI while preserving it in the database with is_deleted=1."""
    login_as(client, 'dr_smith', 'DoctorPass123!@#')

    # Delete record 1
    response = client.post('/records/delete/1', follow_redirects=True)
    assert response.status_code == 200
    assert b"archived" in response.data

    # Verify record 1 no longer appears in active list
    list_res = client.get('/records/')
    assert b"Hypertension (Stage 1)" not in list_res.data

    # Verify record 1 still exists in SQLite database for audit integrity
    with app.app_context():
        record = query_db("SELECT is_deleted FROM medical_records WHERE id = 1", one=True)
        assert record['is_deleted'] == 1


def test_sql_injection_resistance_in_search(client):
    """
    SQL Injection Test:
    Submitting classic SQLi payload `' OR '1'='1` or `' UNION SELECT`
    must be treated as literal string search and not alter the query syntax.
    """
    login_as(client, 'john_doe', 'PatientPass123!@#')

    sqli_payload = "' OR '1'='1' --"
    response = client.get(f'/records/?q={sqli_payload}')
    assert response.status_code == 200
    # The payload does not match any literal diagnosis, so 0 records found
    assert b"No medical records found" in response.data
    # Crucially, Jane Roe's record was NOT leaked by the OR clause
    assert b"Seasonal Allergic Rhinitis" not in response.data


def test_xss_sanitization_in_medical_notes(client):
    """
    XSS Prevention Test:
    Submitting HTML/JavaScript `<script>alert('XSS')</script>` must be stripped safely.
    """
    login_as(client, 'dr_smith', 'DoctorPass123!@#')

    xss_payload = "<script>alert('XSS-TEST')</script>Normal Diagnosis"
    response = client.post('/records/create', data={
        'patient_id': '4',
        'diagnosis': xss_payload,
        'treatment_notes': '<b>Bold note</b><img src=x onerror=alert(1)>',
        'prescription': 'None'
    }, follow_redirects=True)

    assert response.status_code == 200
    # Script tag stripped out
    assert b"<script>" not in response.data
    assert b"alert('XSS-TEST')" not in response.data
    # Safe text retained
    assert b"Normal Diagnosis" in response.data
