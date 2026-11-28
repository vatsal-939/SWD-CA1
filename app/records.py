from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, abort
)
from app.database import query_db, execute_db
from app.logger import log_security_event
from app.security_utils import (
    login_required, role_required, sanitize_input
)

records_bp = Blueprint('records', __name__, url_prefix='/records')


@records_bp.route('/', methods=['GET'])
@login_required
def list_records():
    """
    List medical records filtered strictly by role:
    - Admin: sees all active records
    - Doctor: sees records authored by themselves
    - Patient: sees ONLY their own records (Anti-IDOR)
    Supports search query with parameterized SQL filtering.
    """
    user_id = session.get('user_id')
    user_role = session.get('role')
    search_query = sanitize_input(request.args.get('q', '')).strip()

    # Base query joining patient and doctor names
    sql = """
        SELECT r.id, r.patient_id, r.doctor_id, r.diagnosis, r.treatment_notes,
               r.prescription, r.record_date, r.updated_at,
               p.full_name AS patient_name, p.email AS patient_email,
               d.full_name AS doctor_name
        FROM medical_records r
        JOIN users p ON r.patient_id = p.id
        JOIN users d ON r.doctor_id = d.id
        WHERE r.is_deleted = 0
    """
    params = []

    # Enforce role-based segregation at the database query level
    if user_role == 'patient':
        sql += " AND r.patient_id = ?"
        params.append(user_id)
    elif user_role == 'doctor':
        sql += " AND r.doctor_id = ?"
        params.append(user_id)
    # Admin sees all records (no extra WHERE clause)

    # Apply search filter safely via parameterized query
    if search_query:
        sql += " AND (r.diagnosis LIKE ? OR r.treatment_notes LIKE ? OR p.full_name LIKE ?)"
        wildcard = f"%{search_query}%"
        params.extend([wildcard, wildcard, wildcard])

    sql += " ORDER BY r.record_date DESC, r.id DESC"

    records = query_db(sql, params)

    return render_template('records/list.html', records=records, search_query=search_query)


@records_bp.route('/view/<int:record_id>', methods=['GET'])
@login_required
def view_record(record_id: int):
    """
    View a specific medical record with strict authorization checks:
    - Admin can view
    - Doctor can view only if authored by them
    - Patient can view only if the record belongs to them
    """
    user_id = session.get('user_id')
    user_role = session.get('role')

    record = query_db(
        """
        SELECT r.id, r.patient_id, r.doctor_id, r.diagnosis, r.treatment_notes,
               r.prescription, r.record_date, r.created_at, r.updated_at,
               p.full_name AS patient_name, p.email AS patient_email,
               d.full_name AS doctor_name
        FROM medical_records r
        JOIN users p ON r.patient_id = p.id
        JOIN users d ON r.doctor_id = d.id
        WHERE r.id = ? AND r.is_deleted = 0
        """,
        (record_id,),
        one=True
    )

    if not record:
        flash("Record not found or has been archived.", "warning")
        return redirect(url_for('records.list_records'))

    # Anti-IDOR Authorization Check
    if user_role == 'patient' and record['patient_id'] != user_id:
        log_security_event(
            action="IDOR_ATTEMPT_BLOCKED",
            details=f"Patient {session.get('username')} (ID: {user_id}) attempted to view record ID {record_id} belonging to patient ID {record['patient_id']}",
            status="BLOCKED",
            user_id=user_id
        )
        abort(403)

    if user_role == 'doctor' and record['doctor_id'] != user_id:
        log_security_event(
            action="UNAUTHORIZED_RECORD_ACCESS",
            details=f"Doctor {session.get('username')} attempted to view record ID {record_id} authored by doctor ID {record['doctor_id']}",
            status="WARNING",
            user_id=user_id
        )
        abort(403)

    return render_template('records/view.html', record=record)


@records_bp.route('/create', methods=['GET', 'POST'])
@login_required
@role_required('doctor', 'admin')
def create_record():
    """
    Create a new medical record (Restricted to Doctors and Admins).
    Input is sanitized and stored using parameterized queries.
    """
    user_id = session.get('user_id')
    user_role = session.get('role')

    # Fetch list of patients for the selection dropdown
    patients = query_db("SELECT id, full_name, email FROM users WHERE role = 'patient' ORDER BY full_name ASC")

    # If admin is creating, let them select a doctor or assign to themselves/first doctor
    doctors = []
    if user_role == 'admin':
        doctors = query_db("SELECT id, full_name FROM users WHERE role = 'doctor' ORDER BY full_name ASC")

    if request.method == 'POST':
        patient_id_raw = request.form.get('patient_id')
        doctor_id_raw = request.form.get('doctor_id') if user_role == 'admin' else user_id
        diagnosis = sanitize_input(request.form.get('diagnosis', ''))
        treatment_notes = sanitize_input(request.form.get('treatment_notes', ''))
        prescription = sanitize_input(request.form.get('prescription', ''))

        # Validation
        if not patient_id_raw or not diagnosis or not treatment_notes or not prescription:
            flash("All fields (patient, diagnosis, treatment notes, prescription) are required.", "danger")
            return render_template('records/create.html', patients=patients, doctors=doctors)

        try:
            patient_id = int(patient_id_raw)
            doctor_id = int(doctor_id_raw)
        except ValueError:
            flash("Invalid patient or doctor identifier.", "danger")
            return render_template('records/create.html', patients=patients, doctors=doctors)

        # Validate that patient exists
        patient_exists = query_db("SELECT id FROM users WHERE id = ? AND role = 'patient'", (patient_id,), one=True)
        if not patient_exists:
            flash("Selected patient does not exist.", "danger")
            return render_template('records/create.html', patients=patients, doctors=doctors)

        # Parameterized insert
        new_record_id, _ = execute_db(
            """
            INSERT INTO medical_records (patient_id, doctor_id, diagnosis, treatment_notes, prescription)
            VALUES (?, ?, ?, ?, ?)
            """,
            (patient_id, doctor_id, diagnosis, treatment_notes, prescription)
        )

        log_security_event(
            action="RECORD_CREATED",
            details=f"Medical record ID {new_record_id} created for patient ID {patient_id} by {session.get('username')}",
            status="SUCCESS",
            user_id=user_id
        )

        flash("Medical record created successfully.", "success")
        return redirect(url_for('records.view_record', record_id=new_record_id))

    return render_template('records/create.html', patients=patients, doctors=doctors)


@records_bp.route('/edit/<int:record_id>', methods=['GET', 'POST'])
@login_required
@role_required('doctor', 'admin')
def edit_record(record_id: int):
    """
    Update an existing medical record.
    Doctors can only edit records they authored. Admins can edit any record.
    """
    user_id = session.get('user_id')
    user_role = session.get('role')

    record = query_db(
        """
        SELECT r.*, p.full_name AS patient_name, d.full_name AS doctor_name
        FROM medical_records r
        JOIN users p ON r.patient_id = p.id
        JOIN users d ON r.doctor_id = d.id
        WHERE r.id = ? AND r.is_deleted = 0
        """,
        (record_id,),
        one=True
    )

    if not record:
        flash("Record not found or has been archived.", "warning")
        return redirect(url_for('records.list_records'))

    # Access control: Doctor can only edit records they authored
    if user_role == 'doctor' and record['doctor_id'] != user_id:
        log_security_event(
            action="UNAUTHORIZED_EDIT_ATTEMPT",
            details=f"Doctor {session.get('username')} attempted to edit record ID {record_id} authored by doctor ID {record['doctor_id']}",
            status="BLOCKED",
            user_id=user_id
        )
        abort(403)

    if request.method == 'POST':
        diagnosis = sanitize_input(request.form.get('diagnosis', ''))
        treatment_notes = sanitize_input(request.form.get('treatment_notes', ''))
        prescription = sanitize_input(request.form.get('prescription', ''))

        if not diagnosis or not treatment_notes or not prescription:
            flash("All fields are required.", "danger")
            return render_template('records/edit.html', record=record)

        # Parameterized update with timestamp update
        execute_db(
            """
            UPDATE medical_records
            SET diagnosis = ?, treatment_notes = ?, prescription = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (diagnosis, treatment_notes, prescription, record_id)
        )

        log_security_event(
            action="RECORD_UPDATED",
            details=f"Medical record ID {record_id} updated by {session.get('username')}",
            status="SUCCESS",
            user_id=user_id
        )

        flash("Medical record updated successfully.", "success")
        return redirect(url_for('records.view_record', record_id=record_id))

    return render_template('records/edit.html', record=record)


@records_bp.route('/delete/<int:record_id>', methods=['POST'])
@login_required
@role_required('doctor', 'admin')
def delete_record(record_id: int):
    """
    Soft-delete an existing medical record.
    Preserves audit integrity by retaining the record with is_deleted = 1.
    """
    user_id = session.get('user_id')
    user_role = session.get('role')

    record = query_db(
        "SELECT id, doctor_id, patient_id FROM medical_records WHERE id = ? AND is_deleted = 0",
        (record_id,),
        one=True
    )

    if not record:
        flash("Record not found or already archived.", "warning")
        return redirect(url_for('records.list_records'))

    if user_role == 'doctor' and record['doctor_id'] != user_id:
        log_security_event(
            action="UNAUTHORIZED_DELETE_ATTEMPT",
            details=f"Doctor {session.get('username')} attempted to delete record ID {record_id} authored by doctor ID {record['doctor_id']}",
            status="BLOCKED",
            user_id=user_id
        )
        abort(403)

    # Perform soft-delete
    execute_db(
        "UPDATE medical_records SET is_deleted = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (record_id,)
    )

    log_security_event(
        action="RECORD_DELETED",
        details=f"Medical record ID {record_id} archived (soft-deleted) by {session.get('username')}",
        status="SUCCESS",
        user_id=user_id
    )

    flash("Medical record has been securely archived.", "info")
    return redirect(url_for('records.list_records'))
