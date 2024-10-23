-- Drop the existing database (uncomment if you want to drop it every time)
-- DROP DATABASE IF EXISTS authentication;

-- Create the authentication database
CREATE DATABASE authentication;

-- Connect to the authentication database
\c authentication;

-- Create the AUTHORIZATIONS table
CREATE TABLE AUTHORIZATIONS (
    authorizationId SERIAL PRIMARY KEY,
    roleName VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(500)
);

-- Create the USERS table
CREATE TABLE USERS (
    userID SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    hashPassword VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    contactNumber VARCHAR(20) NOT NULL UNIQUE,
    createdAt TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accountLocked BOOLEAN DEFAULT FALSE,
    authorizationId INT REFERENCES AUTHORIZATIONS(authorizationId)
);

-- Insert initial data into AUTHORIZATIONS
INSERT INTO AUTHORIZATIONS (roleName, description)
VALUES 
    ('Finance Manager', 'The head of the finance department'),
    ('Billing Specialist', 'The one who processes the patients billings'),
    ('System Admin', 'Overall system administrator'),
    ('Claims Specialist', 'Handles insurance claims'),
    ('Medical Staff', 'Medical staff support patient care and manage administrative tasks and appointments'),
    ('Doctor', 'Diagnose and treat medical conditions'),
    ('Patient', 'Individuals receiving medical care and treatment'),
    ('PMS Admin', 'Handles the organizational and operational aspects of healthcare facilities'),
    ('LMS Admin', 'The one who can manipulate the inventory and room management'),
    ('Hospital Staff', 'Can only view the available supplies and room availability');

-- Optional: Insert test data into USERS (you can modify this as necessary)
INSERT INTO USERS (username, hashPassword, email, contactNumber, authorizationId)
VALUES 
    ('finmanager', 'fin123', 'finmanager@company.com', '09210000004', 1),
    ('billingspec', 'billing123', 'billingspec@company.com', '09210000005', 2),
    ('sysadmin', 'admin123', 'sysadmin@company.com', '09210000006', 3),
    ('claimsspec', 'claims123', 'claimsspec@company.com', '09210000007', 4),
    ('pms_user', 'pms123', 'pmsuser@company.com', '09210000008', 8),
    ('lms_user', 'lms123', 'lmsuser@company.com', '09210000009', 9);