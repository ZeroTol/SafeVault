CREATE DATABASE SafeVault;
GO
USE SafeVault;
GO

CREATE TABLE Users (
                       UserID INT PRIMARY KEY IDENTITY(1,1),
                       Username NVARCHAR(100) NOT NULL UNIQUE,
                       Email NVARCHAR(254) NOT NULL UNIQUE,
                       PasswordHash NVARCHAR(255) NOT NULL,
                       CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE FinancialRecords (
                                  RecordID INT PRIMARY KEY IDENTITY(1,1),
                                  UserID INT NOT NULL,
                                  Amount DECIMAL(18,2) NOT NULL CHECK (Amount >= 0),
                                  Description NVARCHAR(500) NULL,
                                  CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
                                  CONSTRAINT FK_Records_Users FOREIGN KEY (UserID) REFERENCES Users(UserID)
);

ALTER TABLE Users
    ADD Role NVARCHAR(20) NOT NULL
  CONSTRAINT DF_Users_Role DEFAULT 'User'
  CONSTRAINT CK_Users_Role CHECK (Role IN ('Admin', 'User', 'Guest'));

CREATE INDEX IX_Users_Username ON Users(Username);

ALTER TABLE Users
    ADD FailedLoginCount INT NOT NULL CONSTRAINT DF_Users_Failed DEFAULT 0,
      LockoutUntilUtc  DATETIME2 NULL;

CREATE TABLE LoginAudit (
                            AuditID    BIGINT IDENTITY(1,1) PRIMARY KEY,
                            Username   NVARCHAR(100) NOT NULL,
                            IpAddress  NVARCHAR(64)  NULL,
                            Outcome    NVARCHAR(20)  NOT NULL,
                            CreatedUtc DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE INDEX IX_LoginAudit_Username_Created ON LoginAudit(Username, CreatedUtc DESC);