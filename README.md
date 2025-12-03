Tech Stack
🔹 Frontend

React.js

Tailwind CSS

Lucide Icons

Axios

Responsive admin dashboard

🔹 Backend

Python Flask

Tesseract OCR

Fraud Scoring Engine

Address Verification API

Device Fingerprint Tracking

Face Matching Service (Aadhaar ↔ Live Photo)

🔹 Database

MySQL

Tables:

users

documents

device_logs

audit_logs

🔹 AI/ML

PyTesseract (OCR extraction)

FuzzyWuzzy / spaCy (Name similarity)

CNN (Forgery/tampering planned)




Milestones & Features (Updated for SmartKYC Project)
Milestone 1: Document Upload & OCR Processing
Features Included

Upload Aadhaar, PAN, Driving License, Utility Bill

OCR extraction using Tesseract

Extracted data fields: Name, ID Number, DOB, Address

Normalization and metadata storage

Device fingerprint capture (IP, browser, user agent, device hash, timestamp)

Backend APIs

Upload document

Generate OCR and metadata

Store document info in MySQL

Frontend Implementation

Document upload screen

OCR preview

Masked output for sensitive ID numbers

Milestone 2: Verification Engine & Fraud Detection
Verification Logic Added

Aadhaar number format and validity mock check

PAN number validation

Driving License number validation

Address extraction and verification using PIN-based lookup

Name matching using similarity model

Fraud Detection Logic

Forgery/tampering indicators from OCR patterns

Duplicate ID number detection

Device behavior checks

Same device uploading many docs

Same user using multiple devices

High document upload frequency

Face match check between Aadhaar photo and live photo

Fraud risk scoring model producing Low, Medium, or High risk level

Admin Dashboard Features

Document status update (Verify, Reject, Delete)

PAN correction workflow

Risk assessment panel

Device fingerprint visibility

Address validation button

Milestone 3: Audit Trail, Compliance, and Monitoring
Features Implemented

Complete logging system for:

Admin actions

System-generated fraud alerts

Verification decisions

Audit Trail UI

Filter by user, action, date range

Quick date selection (Today, Last 24h, Last 7 days)

Drill-down view showing complete event data

CSV export option

Features Planned

Real-time fraud alert pipeline

AML rules detecting high-risk addresses, devices, and patterns

Automatic escalation of suspicious users

Milestone 4: AI Models & System Improvements
Planned Enhancements

CNN-based forgery detection for document images

GNN for:

user-to-device relationship mapping

anomaly detection based on upload behavior

Auto-block user if:

Risk score exceeds threshold

Suspicious device activity detected

Invalid or fake document patterns identified

Deployment Targets

API containerization

Cloud deployment on AWS / Render / Railway

Load balancing and async task queues
Rule-based + ML-based fraud scoring

Device anomaly detection model
