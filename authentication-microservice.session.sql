CREATE TABLE AUTHORIZATIONS (
    authorizationId INT PRIMARY KEY NOT NULL AUTO_INCREMENT
    ,roleName VARCHAR(255) NOT NULL UNIQUE
    ,description VARCHAR(500)
)

CREATE TABLE USERS (
    userID INT PRIMARY KEY NOT NULL AUTO_INCREMENT 
    ,username VARCHAR(255) NOT NULL UNIQUE
    ,hashPassword VARCHAR(255) NOT NULL UNIQUE
    ,email VARCHAR(255) NOT NULL UNIQUE
    ,contactNumber VARCHAR(20) NOT NULL UNIQUE
    ,createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ,updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ,authorizationId INT 
    ,FOREIGN KEY (authorizationId) REFERENCES AUTHORIZATIONS(authorizationId)
)

INSERT INTO AUTHORIZATIONS (roleName, description)
VALUES ('Finance Head', 'The head of the finance department'),
       ('Billing Specialist', 'The one who processes the patients billings');

-- SAMPLE ONLY
INSERT INTO USERS (username, hashPassword, email, contactNumber, authorizationId)
VALUES ('dominique', '32768:8:1$zBjykVE9iwQjDjRI$5194baa4c18417e6aef1634116a82aa83bbba43d8dedb716e9d058d448ca0e23b9d414811f20656b3c97fd3ed2833fc8d48323acf6ba225bd8e0ab36c9608fc7', 
		'shanejain@gmail.com', 09213373133, 1)