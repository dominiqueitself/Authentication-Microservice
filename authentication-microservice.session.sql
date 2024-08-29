CREATE TABLE AUTHORIZATIONS (
    authorization_id INT PRIMARY KEY NOT NULL AUTO_INCREMENT
    ,role_name VARCHAR(255) NOT NULL UNIQUE
    ,description VARCHAR(500)
)

CREATE TABLE USERS (
    user_id INT PRIMARY KEY NOT NULL AUTO_INCREMENT 
    ,username VARCHAR(255) NOT NULL UNIQUE
    ,hashed_password VARCHAR(255) NOT NULL UNIQUE
    ,email VARCHAR(255) NOT NULL UNIQUE
    ,contact_number VARCHAR(20) NOT NULL UNIQUE
    ,account_locked BOOLEAN DEFAULT FALSE
    ,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ,updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ,authorization_id INT 
    ,FOREIGN KEY (authorization_id) REFERENCES AUTHORIZATIONS(authorization_id)
)

INSERT INTO AUTHORIZATIONS (role_name, description)
VALUES ('Finance Manager', 'The head of the finance department'),
       ('Billing Specialist', 'The one who processes the patients billings');

-- SAMPLE ONLY
INSERT INTO USERS (username, hashed_password, email, contact_number, authorization_id)
VALUES ('dominique', '32768:8:1$zBjykVE9iwQjDjRI$5194baa4c18417e6aef1634116a82aa83bbba43d8dedb716e9d058d448ca0e23b9d414811f20656b3c97fd3ed2833fc8d48323acf6ba225bd8e0ab36c9608fc7', 
		'shanejain@gmail.com', 09213373133, 1)
